/*
    Airodump CSV Tools v0.5
    Merges and parses Airodump CSV files and outputs them to CSV, HTML, or text.
    Copyright (C) 2013-2015 Christopher Bolduc

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "csvtools.h"

// Boolean Globals
int onlyAddCommon;
int onlyAddNew;
int onlyAddOld;
int onlyShowKnown;
int deltaSpecified;
int text_brief;

// Other Globals
int verbosity;
int numInputFiles;
int minPower;
int maxPower;
int minPowerDelta;
int mac_db_sz;
int ap_count;
int sta_count;
FILE *kmlFile, *textFile, *htmlFile, *csvFile;
macdb *mac_database, *known_macs, *known_ips;

int compareApByMac ( const void *p1, const void *p2 ) {
  const ap *ap1 = (ap*) p1;
  const ap *ap2 = (ap*) p2;

  return strcmp (ap1->bssid, ap2->bssid);
}

int compareApByPwr ( const void *p1, const void *p2 ) {
  const ap **app1 = (ap**) p1;
  const ap **app2 = (ap**) p2;

  const ap *ap1 = *app1;
  const ap *ap2 = *app2;

  return ap2->power - ap1->power; // sort highest to lowest
}

int compareStaByMac ( const void *p1, const void *p2 ) {
  const enddev *e1 = (enddev*) p1;
  const enddev *e2 = (enddev*) p2;

  return strcmp (e1->station_mac, e2->station_mac);
}

int compareStaByPwr ( const void *p1, const void *p2 ) {
  const enddev **ep1 = (enddev**) p1;
  const enddev **ep2 = (enddev**) p2;

  const enddev *e1 = *ep1;
  const enddev *e2 = *ep2;
  if (e1->power > e2->power) return -1; // sort highest to lowest
  if (e1->power < e2->power) return 1;
  return 0;
}

int compareMacdb ( const void *p1, const void *p2 ) {
  const macdb *d1 = (macdb*) p1;
  const macdb *d2 = (macdb*) p2;

  return strcmp (d1->mac, d2->mac);
}

// Replace a character in a string
char *str_replace(char *s, char old, char new) {
  char *p = s;

  while(*p) {
    if(*p == old)
    *p = new;
    ++p;
  }

  return s;
}

int strToTime (datetime *dest, char *str) {
  return sscanf (str, "%d-%d-%d %d:%d:%d",
      &(dest->year),
      &(dest->month),
      &(dest->day),
      &(dest->hour),
      &(dest->minute),
      &(dest->second));
}

int daysInMonth (int month, int year) {
  int leapyear = 0;

  if (month > 12 || month < 1) {
    printf("daysInMonth(): Invalid month\n");
    return -1;
  }
  if (year % 100 == 0 && year % 400 != 0) {
    leapyear = 0;
  } else if (year % 4 == 0) {
    leapyear = 1;
  } else {
    leapyear = 0;
  }

  switch(month) {
  case 2:
  if (leapyear)
    return 29;
  return 28;
  case 4:
  case 6:
  case 9:
  case 11:
    return 30;
  default:
    return 31;
  }
}

// Places in delta the amount of time between d1 and d2
void dateDiff (datetime *delta, const datetime *d1, const datetime *d2) {
  memcpy(delta, d1, sizeof(datetime));

  if (delta->second < d2->second) {
    delta->minute--;
    delta->second += 60;
  }
  delta->second -= d2->second;
  if (delta->minute < d2->minute) {
    delta->hour--;
    delta->minute += 60;
  }
  delta->minute -= d2->minute;
  if (delta->hour < d2->hour) {
    delta->day--;
    delta->hour += 24;
  }
  delta->hour -= d2->hour;
  if (delta->day < d2->day) {
    delta->month--;
    delta->day += delta->month <= 0 ? daysInMonth(delta->month+12, delta->year-1) : daysInMonth(delta->month, delta->year);
  }
  delta->day -= d2->day;
  if (delta->month < d2->month) {
    delta->year--;
    delta->month += 12;
  }
  delta->month -= d2->month;
  if (delta->year < 0) {
    // d1 is later than d2
    dateDiff(delta, d2, d1);
  }
}

// Returns 1 if d1 > d2, -1 if d2 > d1, 0 if equal
int compareDates (datetime *d1, datetime *d2) {
  if (d1->year > d2->year) return 1;
  if (d1->year < d2->year) return -1;
  if (d1->month > d2->month) return 1;
  if (d1->month < d2->month) return -1;
  if (d1->day > d2->day) return 1;
  if (d1->day < d2->day) return -1;
  if (d1->hour > d2->hour) return 1;
  if (d1->hour < d2->hour) return -1;
  if (d1->minute > d2->minute) return 1;
  if (d1->minute < d2->minute) return -1;
  if (d1->second > d2->second) return 1;
  if (d1->second < d2->second) return -1;
  return 0;
}

// Free the linked list of APs
void free_ap (ap *s) {
  if (s == NULL) return;
  free_ap(s->next);
  free(s);
}

// Free the linked list of Enddevs
void free_enddev (enddev *e) {
  if (e == NULL) return;
  free_enddev(e->next);
  free(e);
}

// Free the linked list of GPS times and coordinates
void free_gps (gps *g) {
  if (g == NULL) return;
  free_gps(g->next);
  free(g);
}

int send_info_udp(char *hostname, int portno, char *msg) {
    int sockfd, n;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        return 1;
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
//    serveraddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    serveraddr.sin_port = htons(portno);

    /* send the message to the server */
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, msg, strlen(msg), 0, (const struct sockaddr *) &serveraddr, (socklen_t) serverlen);
    if (n < 0)
      error("ERROR in sendto");

    return 0;
}

// http://cboard.cprogramming.com/linux-programming/105923-c-program-play-sound.html
// 2015-08-18
void play_sound (char *path) {
  pid_t x;      // a special kind of int
//  char kil[20] = "kill -s 9 ";

  x = fork();   /* now there's actually two "x"s:
if fork succeeds, "x" to the CHILD PROCESS is the return value of fork (0)
and "x" to the PARENT PROCESS is the actual system pid of the child process.*/

  if (x < 0) {  // just in case fork fails 
    puts("fork failure");
    return;
  }
  else if (x == 0) { // therefore this block will be the child process 
    execlp("mpg123", "mpg123", "-q", path, (char *)NULL);
  }
/*                   // see GNU docs, "system" also works                
  else {
    printf("from parent: mpg123 is pid %d\nENTER to quit\n", x);
    sprintf(kil,"%s%d",kil,x);
    getchar();  // wait for user input
    system(kil);
    printf("All ");
  }
*/
}

// This is a separate function from getWord in case the ESSID has commas in it
long getEssid(char *currWord, char *buffer, long i, long lSize) {
  long lastComma = 0;
  int j = i;
  // Skip leading whitespace
  while (i < lSize && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

  while (j < lSize-1) {
    if (buffer[j] == '\r' && buffer[j+1] == '\n') {
      break;
    }
    if (buffer[j] == ',') {
      lastComma = j;
    }
    j++;
  }

  j=0;
  while (i < lastComma && i < lSize-1) {
    currWord[j] = buffer[i];
    i++;
    j++;
  }
  i++;
  j++;
  currWord[j] = '\0';
  return i;
}

// Reads one word from the input file (buffer) and places it into currWord
// Returns the position in buffer
long getWord(char *currWord, char *buffer, long i, long lSize) {
  long j=0;

  // Skip leading whitespace
  while (i < lSize && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

  while (i < lSize-1) {
    if (buffer[i] == '\r' && buffer[i+1] == '\n') {
      // Why, Microsoft?
      i += 2;
      currWord[j] = '\0';
//      printf ("getWord: %s\n", currWord);
      return i;
    }
    if (buffer[i] == ',' || buffer[i] == '\n') {
      currWord[j] = '\0';
//      printf ("getWord: %s\n", currWord);
      i++;
      return i;
    }
    currWord[j] = buffer[i];
    i++;
    j++;
  }
  return i;
}

// Finds an AP in the linked list given the BSSID (key)
ap *findApByBSSID (ap *s, char *key) {
  if (!s) return NULL;
  if (strcmp (s->bssid, key) == 0) {
//    printf("Found %s\n", key);
    return s;
  }
  return findApByBSSID(s->next, key);
}

// Binary search for the Vendor
// Requires macdb to be a sorted array
char *findVendorByMACBin (macdb * m, char * key) {
  int first, middle, last;
//  printf ("Searching for: %s\n", key);
  if (!m) return "";

/* This was to check for segfaults
  printf("Vendors: %d\n", mac_db_sz); 
  int i;
  char *a, *b;
  for (i=0; i<mac_db_sz; i++) {
    a = m[i].mac;
    b = m[i].vendor;
  }
  printf("all vendors done\n");
*/
  first = 0;
  last = mac_db_sz - 1;
  middle = (first + last) / 2;

  while (first <= last) {
    if (strcmp(m[middle].mac, key) < 0) {
      first = middle + 1;
    } else if (strcmp(m[middle].mac, key) == 0) {
//      printf ("MAC: %s VEN: %s\n", m[middle].mac, m[middle].vendor);
      return m[middle].vendor;
    } else {
      last = middle - 1;
    }
    middle = (first + last) / 2;
  }
//  printf ("Not found: %s\n", key);
  return ""; // not found
}

char *findVendorByMAC (macdb * m, char * key) {
//  printf ("Searching for: %s\n", key);
  if (!m) return "";
  if (strcmp(m->mac, key) == 0) return m->vendor;
//  if (m->next == NULL) return "";
  return findVendorByMAC(m->next, key);
}

// Finds an Enddev in the linked list given the Station MAC (key)
enddev *findEnddevByMAC (enddev *e, char *key) {
  if (strcmp (e->station_mac, key) == 0) return e;
  if (e->next == NULL) return NULL;
  return findEnddevByMAC(e->next, key);
}

void printAPAlert (ap *a) {
  printf ("BSSID %s seen at %s", a->bssid, a->last_time_seen);
}

// Prints a single AP to a file with its max power level 
void printAPPowerToFile (ap *a, FILE *f) {
//  printf ("%s, %d, %s%s", a->bssid, a->maxPwrLevel, a->maxPwrTime, CRLF);
  fprintf (f, "%s, %d, %s%s", a->bssid, a->maxPwrLevel, a->maxPwrTime, CRLF);
}

void printAPPowerToFileRec (ap *a, FILE *f) {
  int result;
  int i;
  ap *currAp = a;

  if (a == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  printAPPowerToFile (a, f);

  result = ferror (f);
  if (result) {
    printf ("printAPsPowersToFile fprintf returned error: %d\n", result);
    return;
  }
  printAPPowerToFileRec (a->next, f);
}

void printEndDevicesPowerToFile (enddev *e, FILE *f) {
  fprintf (f, "%s, %d, %s%s", e->station_mac, e->maxPwrLevel, e->maxPwrTime, CRLF);
//  printf ("%s, %d, %s%s", e->station_mac, e->maxPwrLevel, e->maxPwrTime, CRLF);
}

// Prints power levels from a linked list of Enddevs (e) to a file (f)
void printEndDevicesPowerToFileRec (enddev *e, FILE *f) {
  int result;
  int i;
  enddev *curr = e;

  if (e == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  printEndDevicesPowerToFile (e, f);

  result = ferror (f);
  if (result) {
    printf ("printEndDevicesPowersToFile fprintf returned error: %d\n", result);
    return;
  }
  printEndDevicesPowerToFileRec (e->next, f);
}

// sz is populated by the function
char *readFileToString(FILE *pFile, long *sz) {
  long lSize;
  char *buffer;
  size_t result;

  // obtain file size
  fseek (pFile, 0, SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  // allocate memory to contain the whole file
  buffer = (char*) malloc(sizeof(char) * lSize);
  if (buffer == NULL) {
    fputs ("Memory error\n", stderr);
    exit(2);
  }

  // copy the file into the buffer
  result = fread (buffer, 1, lSize, pFile);
  if (result != lSize) {
    fputs ("Reading error\n", stderr);
    exit(3);
  }
//  fclose(pFile);
  *sz = lSize;
  return buffer;
}

void readAPPowerFromFile (ap *first, FILE *f) {
  ap *curr;
  char bssid[80];
  char pwrbuf[80];
  char time[80];
  char *buffer;
  int power;
  int result;
  long lSize;

  if (first == NULL) return;
  buffer = readFileToString(f, &lSize);
  long i=0;
  int j=0;
  while (i<lSize) {
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',') {
        bssid[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        printf ("Error: unexpected EOL for bssid %s\nbuffer: %s\n", bssid, buffer);
        return;
      }
      else
        bssid[j] = buffer[i];
      i++;
      j++;
    }
    if (verbosity>=2) printf ("bssid: %s ", bssid);
    while (buffer[i] == ' ') i++;
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',')  {
        pwrbuf[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        printf ("Error: unexpected EOL for bssid %s\n,buffer:%s\n", bssid, buffer);
        return;
      }
      else
        pwrbuf[j] = buffer[i];
      i++;
      j++;
    }
    power = atoi(pwrbuf);
    if (verbosity>=2)  printf ("pwr: %d ", power);
    j=0;
    while (buffer[i] == ' ') i++;
    while (i<lSize) {
      if (buffer[i] == ',' || buffer[i] == '\r' || buffer[i] == '\n') {
        time[j] = '\0';
        i++;
        break;
      }
      else
        time[j] = buffer[i];
      i++;
      j++;
    }
    while (buffer[i] == ' ' || buffer[i] == '\r' || buffer[i] == '\n') i++;
    if (verbosity>=2) printf ("time: %s\n", time);
    curr = findApByBSSID (first, bssid);
    if (curr != NULL) {
      curr->maxPwrLevel = power;
      strcpy(curr->maxPwrTime, time);
    }
  }

  free (buffer);
}

void readEnddevPowerFromFile (enddev *first, FILE *f) {
  enddev *curr;
  char mac[80];
  char pwrbuf[80];
  char time[80];
  char *buffer;
  int power;
  int result;
  long lSize;

  if (first == NULL) return;
  buffer = readFileToString(f, &lSize);
  long i=0;
  int j=0;
  while (i<lSize) {
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',') {
        mac[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        printf ("Error: unexpected EOL for mac %s\n", mac);
        return;
      }
      else
        mac[j] = buffer[i];
      i++;
      j++;
    }
    if (verbosity>=2) printf ("mac: %s ", mac);
    while (buffer[i] == ' ') i++;
    j=0;
    while (i<lSize) {
      if (buffer[i] == ',')  {
        pwrbuf[j] = '\0';
        i++;
        break;
      }
      else if (buffer[i] == '\r' || buffer[i] == '\n') {
        printf ("Error: unexpected EOL for mac %s\n", mac);
        return;
      }
      else
        pwrbuf[j] = buffer[i];
      i++;
      j++;
    }
    power = atoi(pwrbuf);
    if (verbosity>=2) printf ("pwr: %d ", power);
    j=0;
    while (buffer[i] == ' ') i++;
    while (i<lSize) {
      if (buffer[i] == ',' || buffer[i] == '\r' || buffer[i] == '\n') {
        time[j] = '\0';
        i++;
        break;
      }
      else
        time[j] = buffer[i];
      i++;
      j++;
    }
    while (buffer[i] == ' ' || buffer[i] == '\r' || buffer[i] == '\n') i++;
    if (verbosity>=2) printf ("time: %s\n", time);
    curr = findEnddevByMAC (first, mac);
    if (curr != NULL) {
      curr->maxPwrLevel = power;
      strcpy(curr->maxPwrTime, time);
    }
  }

  free (buffer);
}

gps *readGPSFile (ap *firstap, enddev *firsted, FILE *f) {
  gps *g, *g1, *gprev;
  int result;

  gprev = g = g1 = (gps *) malloc (sizeof(gps));

  while (1) {
    result = fscanf (f, "%d-%d-%d %d:%d:%d, %lf, %lf\r\n", &(g->dt.year), &(g->dt.month), &(g->dt.day), &(g->dt.hour), &(g->dt.minute), &(g->dt.second), &(g->lat), &(g->lon));
    if (result == EOF) {
      gprev->next = NULL;
      free(g);
      return g1;
    }
    g->next = (gps *) malloc (sizeof(gps));
    gprev = g;
    g = g->next;
  }
  return g1;
}

void addGPSInfo (ap *firstap, enddev *firsted, gps *firstg) {
  ap *currap = firstap;
  enddev *curred = firsted;
  gps *g = firstg;
  int result;
  int badtime = 0;

  while (currap != NULL) {
//    printf ("Read AP GPS info for: %s\n", currap->bssid);
    result = strToTime (&(currap->mpTime), currap->maxPwrTime);
    if (result == EOF) {
      printf ("Error reading GPS file\n");
      printf ("Max power time: %s\n", currap->maxPwrTime);
      return;
    }
    if (compareDates (&(currap->mpTime), &(g->dt)) == -1) {
      // Skip this AP, too old
      currap = currap->next;
      continue;
    }

    badtime = 0;
    while (compareDates (&(currap->mpTime), &(g->dt)) == 1) {
      // If compareDates returns 0 or -1, the current AP's date is less than or equal to
      // the date in the GPS file we are checking against.
//      printf ("Is %d:%d:%d > %d:%d:%d?\n", currap->mpTime.hour, currap->mpTime.minute, currap->mpTime.second, g->dt.hour, g->dt.minute, g->dt.second);
      g = g->next;
      if (g == NULL) {
        // Date not in range
        badtime = 1;
        break;
      }
    }
    currap->lat = badtime ? 0 : g->lat;
    currap->lon = badtime ? 0 : g->lon;
    g = firstg;
    currap = currap->next;
  }
  while (curred != NULL) {
//    printf ("Reading Station info for: %s\n", curred->station_mac);
    result = strToTime (&(curred->mpTime), curred->maxPwrTime);
    if (result == EOF) {
      printf ("Error reading station info for %s\n", curred->station_mac);
      printf ("Max power time: %s\n", curred->maxPwrTime);
      return;
    }
    if (compareDates (&(curred->mpTime), &(g->dt)) == -1) {
      // Skip this end device, too old
      curred = curred->next;
      continue;
    }

    badtime = 0;
    while (compareDates (&(curred->mpTime), &(g->dt)) == 1) {
      g = g->next;
      if (g == NULL) {
        // Date not in range
        badtime = 1;
        break;
      }
    }
    curred->lat = badtime ? 0 : g->lat;
    curred->lon = badtime ? 0 : g->lon;
    g = firstg;
    curred = curred->next;
  }
}

// Prints a single AP (a) to a file (f)
void printAPToFileKML (ap *a, FILE *f) {
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  if (a->lat == 0.0) return; // no GPS data
  if (onlyShowKnown && strcmp(a->desc, "") == 0) return;
  fprintf(f, "<Placemark>%s"
    "<name>%s (%s)</name>%s"
    "<description>%s", CRLF, strcmp(a->desc, "") == 0 ? a->essid : a->desc, str_replace(a->vendor, '&', ' '), CRLF, CRLF);
  fprintf (f, "Description: %s%s", a->desc, CRLF);
  fprintf (f, "BSSID: %s%s", a->bssid, CRLF);
  fprintf (f, "Vendor: %s%s", str_replace(a->vendor, '&', ' '), CRLF);
  fprintf (f, "First time seen: %s%s", a->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", a->last_time_seen, CRLF);
  fprintf (f, "Channel: %s%s", a->channel, CRLF);
  fprintf (f, "Speed: %s%s", a->speed, CRLF);
  fprintf (f, "Privacy: %s%s", a->privacy, CRLF);
  fprintf (f, "Cipher: %s%s", a->cipher, CRLF);
  fprintf (f, "Authentication: %s%s", a->authentication, CRLF);
  fprintf (f, "Power: %d%s", a->power, CRLF);
  fprintf (f, "Previous Power: %d%s", a->oldPower, CRLF);
  fprintf (f, "Beacons: %s%s", a->beacons, CRLF);
  fprintf (f, "IVs: %s%s", a->ivs, CRLF);
  fprintf (f, "LAN IP: %s%s", a->lan_ip, CRLF);
  fprintf (f, "ID-length: %s%s", a->id_length, CRLF);
  fprintf (f, "ESSID: %s%s", a->essid, CRLF);
  fprintf (f, "Key: %s%s", a->key, CRLF);
  fprintf (f, "Max Power: %d%s", a->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", a->maxPwrTime, CRLF);
  fprintf (f, "IP Address: %s%s", a->ip, CRLF);
  fprintf (f, "File: %s%s%s", a->fileName, CRLF, CRLF);

  fprintf (f, "</description>%s"
    "<Point>%s"
      "<coordinates>%lf,%lf</coordinates>%s"
    "</Point>%s"
  "</Placemark>%s", CRLF, CRLF, a->lon, a->lat, CRLF, CRLF, CRLF);

}

// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileKML (enddev *e, FILE *f) {
  int powerDelta = e->power - e->oldPower;
//  if (powerDelta < 0) powerDelta = -powerDelta;
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  if (e->lat == 0.0) return; // no GPS data
  if (onlyShowKnown && strcmp(e->desc, "") == 0) {
    if (verbosity) printf ("Skipping station: %s\n", e->station_mac); 
    return;
  }
  if (deltaSpecified) {
    if (e->oldPower >= -1 || powerDelta <= minPowerDelta) return;
  }
  fprintf(f, "<Placemark>%s"
    "<name>%s (%s)</name>%s"
    "<description>%s", CRLF, strcmp(e->desc, "") == 0 ? e->station_mac : e->desc, str_replace(e->vendor, '&', ' '), CRLF, CRLF);
  fprintf (f, "Description: %s%s", e->desc, CRLF);
  fprintf (f, "Station MAC: %s%s", e->station_mac, CRLF);
  fprintf (f, "Vendor: %s%s", str_replace(e->vendor, '&', ' '), CRLF);
  fprintf (f, "First time seen: %s%s", e->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", e->last_time_seen, CRLF);
  fprintf (f, "Power: %d%s", e->power, CRLF);
  fprintf (f, "Previous Power: %d%s", e->oldPower, CRLF);
  fprintf (f, "Packet count: %s%s", e->packets, CRLF);
  fprintf (f, "BSSID: %s%s", e->bssid, CRLF);
  fprintf (f, "ESSID: %s%s", e->essid, CRLF);
  fprintf (f, "Probed ESSIDs: %s%s", e->probed_essids, CRLF);
  fprintf (f, "Max Power: %d%s", e->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", e->maxPwrTime, CRLF);
  fprintf (f, "IP address: %s%s", e->ip, CRLF);
  fprintf (f, "File %s%s%s", e->fileName, CRLF, CRLF);
  fprintf (f, "</description>%s"
    "<Point>%s"
      "<coordinates>%lf,%lf</coordinates>%s"
    "</Point>%s"
  "</Placemark>%s", CRLF, CRLF, e->lon, e->lat, CRLF, CRLF, CRLF);
}

// Prints a single AP (a) to a file (f)
void printAPToFileHTML (ap *a, FILE *f) {
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  if (onlyShowKnown && strcmp(a->desc, "") == 0) return;
  fprintf (f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
    "<td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>%s",
    a->bssid, a->vendor, a->first_time_seen, a->last_time_seen, a->prev_last_time_seen, a->channel, a->speed, a->privacy, a->cipher,
    a->authentication, a->power, a->beacons, a->ivs, a->lan_ip, a->id_length, a->essid, a->key, a->desc, a->ip,
    CRLF);
}
/*
// Prints all of the APs in the linked list (a) to a file (f)
void printAPsToFileHTML (ap *a, FILE *f) {
  int result;
  int i;
  ap *currAp = a;

  if (a == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  if (onlyAddNew) {
    if (a->new) printAPToFileHTML (a, f);
  } else if (onlyAddOld) {
    if (a->old) printAPToFileHTML(a, f);
  } else {
    printAPToFileHTML (a, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printAPsToFileHTML fprintf returned error: %d\n", result);
    return;
  }
  printAPsToFileHTML (a->next, f);
}
*/
// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileHTML (enddev *e, FILE *f) {
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  if (onlyShowKnown && strcmp(e->desc, "") == 0) return;
  fprintf (f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>%s", e->station_mac, e->vendor, e->first_time_seen,
    e->last_time_seen, e->prev_last_time_seen, e->power, e->packets, e->bssid, e->essid, e->probed_essids, e->desc, e->ip, CRLF);
}
/*
// Prints a linked list of Enddevs (e) to a file (f)
void printEndDevicesToFileHTML (enddev *e, FILE *f) {
  int result;
  int i;
  enddev *curr = e;

  if (e == NULL) {
    fprintf(f, "%s", CRLF);
    return;
  }
  if (onlyAddNew) {
    if (e->new) printEndDeviceToFileHTML (e, f);
  } else if (onlyAddOld) {
    if (e->old) printEndDeviceToFileHTML (e, f);
  } else {
    printEndDeviceToFileHTML (e, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printEndDevicesToFileHTML fprintf returned error: %d\n", result);
    return;
  }
  printEndDevicesToFileHTML (e->next, f);
}
*/

// Prints a single AP (a) to a file (f)
void printAPToFileCSV (ap *a, FILE *f) {
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  fprintf (f, "%s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s%s",
    a->bssid, a->first_time_seen, a->last_time_seen, a->channel, a->speed, a->privacy, a->cipher,
    a->authentication, a->power, a->beacons, a->ivs, a->lan_ip, a->id_length, a->essid, a->key, CRLF);
}

// Prints all of the APs in the linked list (a) to a file (f)
void printAPsToFileRec (ap *a) {
  int result;
  int i;
  int skip = 1;
  ap *curr = a;
  ap **ap_arr = (ap **) malloc(ap_count * sizeof(ap*));

  for (i=0; i < ap_count; i++) {
    if (curr == NULL) {
      ap_arr[i] = NULL;
//      break; // should not reach this but just in case...
    } else{
       ap_arr[i] = curr;
      curr = curr->next;
    }
  }
  qsort(ap_arr, ap_count, sizeof(ap*), &compareApByPwr);

  for (i=0; i < ap_count; i++) {
    curr = ap_arr[i];

    if (curr == NULL) {
      break;
    }

    skip = 1;
    if (onlyAddNew) {
      if (curr->new) {
        skip = 0;
//        printf("AP is new: %s\n", curr->bssid);
      }
    } else if (onlyAddOld) {
      if (curr->old) {
        skip = 0;
//        printf("AP is old: %s\n", curr->bssid);
      }
    } else {
      skip = 0;
//      printf("OnlyAddNew and OnlyAddOld are off\n");
    }

    if (!skip) {
      printAPToFileCSV (curr, csvFile);
      printAPToFileText (curr, textFile);
      printAPToFileHTML (curr, htmlFile);
      if (kmlFile) printAPToFileKML (curr, kmlFile);
    }
  }
  fprintf(csvFile, "%s", CRLF);
/*
  result = ferror (f);
  if (result) {
    printf ("printAPsToFileCSV fprintf returned error: %d\n", result);
    return;
  }
 */
//  printAPsToFileRec (a->next);
}

// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileCSV (enddev *e, FILE *f) {
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  fprintf (f, "%s, %s, %s, %d, %s, %s, %s%s", e->station_mac, e->first_time_seen,
    e->last_time_seen, e->power, e->packets, e->bssid, e->probed_essids, CRLF);
}

// Prints a linked list of Enddevs (e) to files (text, html, csv)
void printEndDevicesToFileRec (enddev *e) {
  int result;
  int i;
  int skip = 1;
  enddev *curr = e;
  enddev **sta_arr = (enddev **) malloc(sta_count * sizeof(enddev*));

  for (i=0; i < sta_count; i++) {
    if (curr == NULL) {
      sta_arr[i] = NULL;
      // should not get here, but just in case...
    } else {
      sta_arr[i] = curr;
      curr = curr->next;
    }
    if (verbosity >= 2) printf("Added station %s\n", curr->station_mac);
  }
  qsort(sta_arr, sta_count, sizeof(enddev*), &compareStaByPwr);

  for (i=0; i < sta_count; i++) {
    curr = sta_arr[i];
    if (curr == NULL) {
      break;
    }
    skip = 1;
//    printf("i = %d/%d\n", i, sta_count);
//    printf("next station (%d): %s\n", i, curr->station_mac);
    if (onlyAddNew) {
      if (curr->new) skip = 0;
    } else if (onlyAddOld) {
      if (curr->old) skip = 0;
    } else {
      skip = 0;
    }

    if (!skip) {
//      if (verbosity >= 2) printf("Printing to csv/text/html station: %s Pwr: %d\n", curr->station_mac, curr->power);
//      if (verbosity >= 2) printf("Printing station to csv file.\n");
      printEndDeviceToFileCSV (curr, csvFile);
//      if (verbosity >= 2) printf("Printing station to text file.\n");
      printEndDeviceToFileText (curr, textFile);
//      if (verbosity >= 2) printf("Printing station to html file.\n");
      printEndDeviceToFileHTML (curr, htmlFile);
//      if (verbosity >= 2) printf("Printing %s to KML file\n", curr->station_mac);
      if (kmlFile) printEndDeviceToFileKML (curr, kmlFile);
    }
  }
  fprintf(csvFile, "%s", CRLF);
  free(sta_arr); 

/*
  result = ferror (f);
  if (result) {
    printf ("printEndDevicesToFileCSV fprintf returned error: %d\n", result);
    return;
  }
*/
//  printEndDevicesToFileRec (e->next);  // not using recursion anymore
}

// Prints a single ap (a) to a file (f)
void printAPToFileText (ap *a, FILE *f) {
  int powerDelta = a->power - a->oldPower;
//  if (powerDelta < 0) powerDelta = -powerDelta;
  if (a->power < minPower) return;
  if (a->power > maxPower) return;
  if (onlyShowKnown && strcmp(a->desc, "") == 0) return;

/*
  datetime plts, dThresh;
  dateDiff(&plts, &(a->prvtime2), &(a->time2));
  dThresh.year = 0;
  dThresh.month = 0;
  dThresh.day = 0;
  dThresh.hour = 1;
  dThresh.minute = 0;
  dThresh.second = 0;
  if (compareDates(&plts, &dThresh) > 0) {
    fprintf (f, "Above Threshold - AP:  %s ESSID: %s PWR: %d DESC: %s VEN: %s ", a->bssid, a->essid, a->power, a->desc, a->vendor);
  }
*/
  if (deltaSpecified) {
    if (a->oldPower >= -1 || powerDelta <= minPowerDelta) return;
    // We found something, ring a bell
//    printf ("\a");
  }

  if (text_brief) {
    fprintf (f, "%s AP:  %s ESSID: %s PWR: %d DESC: %s VEN: %s%s", a->last_time_seen, a->bssid, a->essid, a->power, a->desc, a->vendor, CRLF);
//    fprintf (f, "SP: %i-%i-%i %i:%i:%i%s", plts.year, plts.month, plts.day, plts.hour, plts.minute, plts.second, CRLF);
    return;
  }

  fprintf (f, "BSSID: %s%s", a->bssid, CRLF);
  fprintf (f, "Vendor: %s%s", a->vendor, CRLF);
  fprintf (f, "First time seen: %s%s", a->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", a->last_time_seen, CRLF);
  fprintf (f, "Previous last time seen: %s%s", a->prev_last_time_seen, CRLF);
//  fprintf (f, "Since previous LTS: %i-%i-%i %i:%i:%i%s", plts.year, plts.month, plts.day, plts.hour, plts.minute, plts.second, CRLF);
  fprintf (f, "Channel: %s%s", a->channel, CRLF);
  fprintf (f, "Speed: %s%s", a->speed, CRLF);
  fprintf (f, "Privacy: %s%s", a->privacy, CRLF);
  fprintf (f, "Cipher: %s%s", a->cipher, CRLF);
  fprintf (f, "Authentication: %s%s", a->authentication, CRLF);
  fprintf (f, "Power: %d%s", a->power, CRLF);
  fprintf (f, "Previous Power: %d%s", a->oldPower, CRLF);
  fprintf (f, "Beacons: %s%s", a->beacons, CRLF);
  fprintf (f, "IVs: %s%s", a->ivs, CRLF);
  fprintf (f, "LAN IP: %s%s", a->lan_ip, CRLF);
  fprintf (f, "ID-length: %s%s", a->id_length, CRLF);
  fprintf (f, "ESSID: %s%s", a->essid, CRLF);
  fprintf (f, "Key: %s%s", a->key, CRLF);
  fprintf (f, "Max Power: %d%s", a->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", a->maxPwrTime, CRLF);
  fprintf (f, "Latitude: %lf%s", a->lat, CRLF);
  fprintf (f, "Longitude: %lf%s", a->lon, CRLF);
  fprintf (f, "File: %s%s", a->fileName, CRLF);
  fprintf (f, "IP Address: %s%s", a->ip, CRLF);
  fprintf (f, "Description: %s%s%s", a->desc, CRLF, CRLF);
}
/*
// Prints a linked list of APs (a) to a file (f)
void printAPsToFileText (ap *a, FILE *f) {
  int i, result;
  ap *currAp = a;

  if (a == NULL) return;
  if (onlyAddNew) {
    if (a->new) printAPToFileText (a, f);
  } else if (onlyAddOld) {
    if (a->old) printAPToFileText (a, f);
  } else {
    printAPToFileText (a, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printAPsToFileText fprintf returned error: %d\n", result);
    return;
  }
  printAPsToFileText (a->next, f);
}
*/
// Prints a single Enddev (e) to a file (f)
void printEndDeviceToFileText (enddev *e, FILE *f) {
  int powerDelta = e->power - e->oldPower;
  char descbuf[256];
//  if (powerDelta < 0) powerDelta = -powerDelta;
  if (e->power < minPower) return;
  if (e->power > maxPower) return;
  if (onlyShowKnown && strcmp(e->desc, "") == 0) return;

/*
  datetime plts, dThresh;
  dateDiff(&plts, &(e->prvtime2), &(e->time2));
  dThresh.year = 0;
  dThresh.month = 0;
  dThresh.day = 0;
  dThresh.hour = 1;
  dThresh.minute = 0;
  dThresh.second = 0;
  if (compareDates(&plts, &dThresh) > 0) {
    fprintf (f, "Above Threshold - AP:  %s ESSID: %s PWR: %d DESC: %s VEN: %s ", e->bssid, e->essid, e->power, e->desc, e->vendor);
  }
*/

  if (deltaSpecified) {
    if (e->oldPower >= -1 || powerDelta <= minPowerDelta) return;
  }
//  play_sound("ding.mp3");
/*
  if (verbosity >= 2) printf ("Sending UDP segment...");
  sprintf(descbuf, "STA: %s (%s) ESSID: %s PWR: %d DESC: %s\n", e->station_mac, e->vendor, e->essid, e->power, e->desc);
  send_info_udp("10.10.10.10", 4000, descbuf);
  if (verbosity >= 2) printf ("done\n");
*/

  if (text_brief) {
    fprintf (f, "%s STA: %s ESSID: %s PWR: %d DESC: %s VEN: %s%s", e->last_time_seen, e->station_mac, e->essid, e->power+100, e->desc, e->vendor, CRLF);
//    fprintf (f, "SP: %i-%i-%i %i:%i:%i%s", plts.year, plts.month, plts.day, plts.hour, plts.minute, plts.second, CRLF);
    return;
  }
  fprintf (f, "Station MAC: %s%s", e->station_mac, CRLF);
  fprintf (f, "Vendor: %s%s", e->vendor, CRLF);
  fprintf (f, "First time seen: %s%s", e->first_time_seen, CRLF);
  fprintf (f, "Last time seen: %s%s", e->last_time_seen, CRLF);
  fprintf (f, "Previous last time seen: %s%s", e->prev_last_time_seen, CRLF);
//  fprintf (f, "Since previous LTS: %i-%i-%i %i:%i:%i%s", plts.year, plts.month, plts.day, plts.hour, plts.minute, plts.second, CRLF);
  fprintf (f, "Power: %d%s", e->power, CRLF);
  fprintf (f, "Previous Power: %d%s", e->oldPower, CRLF);
  fprintf (f, "Packet count: %s%s", e->packets, CRLF);
  fprintf (f, "BSSID: %s%s", e->bssid, CRLF);
  fprintf (f, "ESSID: %s%s", e->essid, CRLF);
  fprintf (f, "Probed ESSIDs: %s%s", e->probed_essids, CRLF);
  fprintf (f, "Max Power: %d%s", e->maxPwrLevel, CRLF);
  fprintf (f, "Max Power Time: %s%s", e->maxPwrTime, CRLF);
  fprintf (f, "Latitude: %lf%s", e->lat, CRLF);
  fprintf (f, "Longitude: %lf%s", e->lon, CRLF);
  fprintf (f, "File: %s%s", e->fileName, CRLF);
  fprintf (f, "IP Address: %s%s", e->ip, CRLF);
  fprintf (f, "Description: %s%s%s", e->desc, CRLF, CRLF);
}

/*
// Prints a linked list of Enddevs (e) to a file (f)
void printEndDevicesToFileText (enddev *e, FILE *f) {
  int i, result;
  enddev *curr = e;

  if (e == NULL) return;
  if (onlyAddNew) {
    if (e->new) printEndDeviceToFileText (e, f);
  } else if (onlyAddOld) {
    if (e->old) printEndDeviceToFileText (e, f);
  } else {
    printEndDeviceToFileText (e, f);
  }

  result = ferror (f);
  if (result) {
    printf ("printEndDevicesToFileText fprintf returned error: %d\n", result);
    return;
  }
  printEndDevicesToFileText (e->next, f);
}
*/

int compareMacDbItems ( const void *p1, const void *p2 ) {
  const macdb *e1 = (macdb*) p1;
  const macdb *e2 = (macdb*) p2;

  return strcmp (e1->mac, e2->mac);
}

// Read the vendor MAC address database into an array //linked list
void readMacDB (char * fileName) {
  FILE *pFile;
  long lSize;
  char buffer[120];
  char *mac, *vendor, *macfile;
  macdb *curr_node;
  int i, ven;
  int lines=0;

  pFile = fopen (fileName, "r");
  if (pFile == NULL) {
   printf ("readMacDB - Error opening file: %s\n", fileName);
   exit(1);
  }

  // Count how many vendors there are
  macfile = readFileToString(pFile, &lSize);
  for (i=0; i < lSize; i++) {
    if(macfile[i] == '\n') lines++;
  }
//  printf("Got %d vendors\n", lines);
  mac_db_sz = lines;

  rewind(pFile);
  mac_database = (macdb *) malloc (lines * sizeof(macdb));

  for (ven=0; ven < lines; ven++) {
    if (fgets (buffer, 120, pFile) == NULL) {
      break;
    }
    curr_node = mac_database + ven;
    mac = curr_node->mac;
    vendor = curr_node->vendor;
    memcpy (mac, buffer, 8);
    mac[8] = '\0';
    for (i=0; i < 8; i++) {
      if (mac[i] == '-') mac[i] = ':';
    }
    memcpy (vendor, buffer + 18, 80);
    for (i=0; i < 80; i++) {
      if (vendor[i] == '\n' || vendor[i] == '\r') {
        vendor[i] = '\0';
        break;
      }
    }
//      printf ("Got ven: %s mac: %s\n", vendor, mac);
  }
  qsort(mac_database, lines, sizeof(macdb), &compareMacDbItems);
}

// Reads a CSV list of known MAC addresses (user-generated)
// So they can be placed next to the AP/station
// "Vendor" in this case is the user-generated comment
void readKnownMacs (char * fileName) {
  FILE *pFile;
  long lSize;
  char buffer[120];
  char *mac, *vendor;
  macdb *curr_node;
  int i;

  pFile = fopen (fileName, "r");

  if (pFile == NULL) {
   printf ("readKnownMacs - Error opening file: %s\n", fileName);
   exit(1);
  }

  while (fgets (buffer, 120, pFile) != NULL) {
    if (known_macs == NULL) {
      known_macs = (macdb *) malloc (sizeof(macdb));
      known_macs->next = NULL;
      curr_node = known_macs;
    } else {
      curr_node->next = (macdb *) malloc (sizeof(macdb));
      curr_node = curr_node->next;
      curr_node->next = NULL;
    }
    mac = curr_node->mac;
    vendor = curr_node->vendor;
    memcpy (mac, buffer, 17); // not sure about 17 (mac address characters)
    mac[17] = '\0';
    for (i=0; i < 8; i++) {
      if (mac[i] == '-') mac[i] = ':';
    }
    for (i=0; i<17; i++) {
      if (mac[i] >= 97 && mac[i] <= 122) {
        mac[i] -= 32; // convert to upper case
      }
    }
    memcpy (vendor, buffer+18, 80);
    for (i=0; i < 80; i++) {
      if (vendor[i] == '\n' || vendor[i] == '\r') {
        vendor[i] = '\0';
        break;
      }
    }
//    printf ("Added %s - %s\n", mac, vendor);
  }
}

// Reads a CSV list of known IP addresses (script-generated)
// So they can be placed next to the AP/station
// "Vendor" in this case is the IP address
void readKnownIPs (char * fileName) {
  FILE *pFile;
  long lSize;
  char buffer[120];
  char *mac, *vendor;
  macdb *curr_node;
  int i;

  pFile = fopen (fileName, "r");

  if (pFile == NULL) {
   printf ("readKnownMacs - Error opening file: %s\n", fileName);
   exit(1);
  }

  while (fgets (buffer, 120, pFile) != NULL) {
    if (known_ips == NULL) {
      known_ips = (macdb *) malloc (sizeof(macdb));
      known_ips->next = NULL;
      curr_node = known_ips;
    } else {
      curr_node->next = (macdb *) malloc (sizeof(macdb));
      curr_node = curr_node->next;
      curr_node->next = NULL;
    }
    mac = curr_node->mac;
    vendor = curr_node->vendor;
    memcpy (mac, buffer, 17); // not sure about 17 (mac address characters)
    mac[17] = '\0';
    for (i=0; i < 8; i++) {
      if (mac[i] == '-') mac[i] = ':';
    }
    for (i=0; i<17; i++) {
      if (mac[i] >= 97 && mac[i] <= 122) {
        mac[i] -= 32; // convert to upper case
      }
    }
    memcpy (vendor, buffer+18, 80);
    for (i=0; i < 80; i++) {
      if (vendor[i] == '\n' || vendor[i] == '\r') {
        vendor[i] = '\0';
        break;
      }
    }

//    printf ("Added %s - %s\n", mac, vendor);
  }
}

// Reads a CSV file (fileName)
// Inserts the APs into a linked list of APs (firstAp)
// Inserts the Enddevs into a linked list of Enddevs (firstEnddev)
// Returns a devset with the addresses of the first AP and Devset
// because the values passed in will be NULL if this is the first file read
devset readCSVFile (char * fileName, ap *firstAp, enddev *firstEnddev, const int lastFile) {
  FILE *pFile;
  long i=0, j=0, k=0;
  long lSize;
  char *buffer;
  char mac[9];
  char power[5];
  char currWord[80];
  char description[16][80];
  char first_time_seen[80];
  int keepDate;
  size_t result;
  ap *currAp = NULL;
  ap *lastAp = firstAp;
  ap *tempAp = NULL;
  enddev *currEnddev = NULL;
  enddev *lastEnddev = firstEnddev;
  enddev *tempEnddev = NULL;
  devset dset;

  pFile = fopen (fileName, "r");

  if (pFile == NULL) {
   printf ("readCSVFile - Error opening file: %s\n", fileName);
   exit(1);
  }

  if (lastAp != NULL) while (lastAp->next != NULL) lastAp = lastAp->next;
  if (lastEnddev != NULL) while (lastEnddev->next != NULL) lastEnddev = lastEnddev->next;
  
  // obtain file size
  fseek (pFile, 0, SEEK_END);
  lSize = ftell (pFile);
  rewind (pFile);

  // allocate memory to contain the whole file
  buffer = (char*) malloc(sizeof(char) * lSize);
  if (buffer == NULL) {
    fputs ("Memory error\n", stderr);
    exit(2);
  }

  // copy the file into the buffer
  result = fread (buffer, 1, lSize, pFile);
  if (result != lSize) {
    fputs ("Reading error\n", stderr);
    exit(3);
  }
 
  // Skip the first two lines
  j=0;
  for (i=0; i < lSize-1; i++) {
    if (buffer[i] == '\n') j++;
    if (j == 2) {
      i++;
      break;
    }
  }

  if (verbosity >= 2) printf ("Processing %s\n", fileName);
  // Read the list of aps
  while (i < lSize-1) {
    //Check if we are at the end of the ap list
    if (buffer[i] == '\n') {
      i++;
      break;
    } else if (buffer[i]== '\r' && buffer[i+1] == '\n') {
      i += 2;
      break;
    }
    // Read the next AP
    i = getWord (currWord, buffer, i, lSize);
    keepDate = 0;
    if (firstAp == NULL) {
      firstAp = (ap *) malloc (sizeof(ap));
      firstAp->next = NULL;
      firstAp->new = lastFile ? 1 : 0;
      firstAp->old = 0;
      firstAp->maxPwrLevel = -100;
      firstAp->prev_last_time_seen[0] = '\0';
      bzero(firstAp->maxPwrTime, 80);
      firstAp->lat = firstAp->lon = 0.0;
      lastAp = currAp = firstAp;
      ap_count++;
    } else {
      currAp = findApByBSSID (firstAp, currWord);
      if (currAp == NULL) {
        currAp = (ap *) malloc (sizeof(ap));
        currAp->next = NULL;
        currAp->new = lastFile ? 1 : 0;
        currAp->old = 0;
        currAp->prev_last_time_seen[0] = '\0';
        currAp->maxPwrLevel = -100;
        bzero(currAp->maxPwrTime, 80);
        currAp->lat = currAp->lon = 0.0;
        lastAp->next = currAp;
        lastAp = currAp;
        ap_count++;
      } else {
        currAp->new = 0;
        currAp->old = lastFile ? 1 : 0;
        strcpy(first_time_seen, currAp->first_time_seen);
        keepDate = 1;
      }
    }

    strcpy (currAp->bssid, currWord);
    memcpy (mac, currAp->bssid, 8);
    mac[8] = '\0';
    strcpy (currAp->vendor, findVendorByMACBin (mac_database, mac));
    // "Vendor" is actually the description in this case
    strcpy (currAp->desc, findVendorByMAC (known_macs, currAp->bssid));
    // Do the same for the IP address
    strcpy (currAp->ip, findVendorByMAC (known_ips, currAp->bssid));
    i = getWord (currAp->first_time_seen, buffer, i, lSize);
    if (keepDate) strcpy(currAp->first_time_seen, first_time_seen);
    i = getWord (currAp->last_time_seen, buffer, i, lSize);
    if (!lastFile) strcpy(currAp->prev_last_time_seen, currAp->last_time_seen);
    i = getWord (currAp->channel, buffer, i, lSize);
    i = getWord (currAp->speed, buffer, i, lSize);
    i = getWord (currAp->privacy, buffer, i, lSize);
    i = getWord (currAp->cipher, buffer, i, lSize);
    i = getWord (currAp->authentication, buffer, i, lSize);
    i = getWord (power, buffer, i, lSize);
    currAp->oldPower = 0;
    if (currAp->old) currAp->oldPower = currAp->power;
    currAp->power = atoi(power);
    i = getWord (currAp->beacons, buffer, i, lSize);
    i = getWord (currAp->ivs, buffer, i, lSize);
    i = getWord (currAp->lan_ip, buffer, i, lSize);
    i = getWord (currAp->id_length, buffer, i, lSize);
    i = getEssid (currAp->essid, buffer, i, lSize);
    i = getWord (currAp->key, buffer, i, lSize);
    strcpy (currAp->fileName, fileName);
    // I dont actually use the time1 and time2 for anything yet.
    memcpy(&(currAp->prvtime2), &(currAp->time2), sizeof(datetime));
    sscanf (currAp->first_time_seen, "%d-%d-%d %d:%d:%d", 
      &(currAp->time1.year),
      &(currAp->time1.month),
      &(currAp->time1.day),
      &(currAp->time1.hour),
      &(currAp->time1.minute),
      &(currAp->time1.second));
    sscanf (currAp->last_time_seen, "%d-%d-%d %d:%d:%d",
      &(currAp->time2.year),
      &(currAp->time2.month),
      &(currAp->time2.day),
      &(currAp->time2.hour),
      &(currAp->time2.minute),
      &(currAp->time2.second));
    if (currAp->power > currAp->maxPwrLevel && currAp->power < -1) {
      currAp->maxPwrLevel = currAp->power;
      strcpy(currAp->maxPwrTime, currAp->last_time_seen);
    }
    if (strcmp(currAp->maxPwrTime, "") == 0) strcpy(currAp->maxPwrTime, currAp->last_time_seen);
    if (verbosity >= 2) printf("added ap: %s\n", currAp->bssid);
  }

  // Skip the description line
  while (i < lSize) {
    if (buffer[i] == '\n') {
      i++; break;
    }
    i++;
  }

  // Read the end devices
  while (i < lSize) {
    //Check if we are at the end of the end device list
    if (buffer[i] == '\n') {
      i++;
      break;
    } else if (buffer[i]== '\r' && buffer[i+1] == '\n') {
      i += 2;
      break;
    }
    i = getWord (currWord, buffer, i, lSize);
    keepDate = 0;
    if (firstEnddev == NULL) {
      firstEnddev = (enddev *) malloc (sizeof(enddev));
      firstEnddev->next = NULL;
      firstEnddev->new = lastFile ? 1 : 0;
      firstEnddev->old = 0;
      firstEnddev->prev_last_time_seen[0] = '\0';
      firstEnddev->maxPwrLevel = -100;
      firstEnddev->lat = firstEnddev->lon = 0.0;
      bzero(firstEnddev->maxPwrTime, 80);
      lastEnddev = currEnddev = firstEnddev;
      sta_count++;
    } else {
      currEnddev = findEnddevByMAC (firstEnddev, currWord);
      if (currEnddev == NULL) {
        currEnddev = (enddev *) malloc (sizeof(enddev));
        currEnddev->next = NULL;
        currEnddev->new = lastFile ? 1 : 0;
        currEnddev->old = 0;
        currEnddev->prev_last_time_seen[0] = '\0';
        currEnddev->maxPwrLevel = -100;
        bzero(currEnddev->maxPwrTime, 80);
        currEnddev->lat = currEnddev->lon = 0.0;
        lastEnddev->next = currEnddev;
        lastEnddev = currEnddev;
        sta_count++;
      } else {
        strcpy (first_time_seen, currEnddev->first_time_seen);
        currEnddev->new = 0;
        currEnddev->old = lastFile ? 1 : 0;
        keepDate = 1;
      }
    }
    strcpy (currEnddev->station_mac, currWord);
    memcpy (mac, currEnddev->station_mac, 8);
    mac[8] = '\0';
    strcpy (currEnddev->vendor, findVendorByMACBin (mac_database, mac));
    // "Vendor" is actually the description in this case
    strcpy (currEnddev->desc, findVendorByMAC (known_macs, currEnddev->station_mac));
    // Do the same for the IP address
    strcpy (currEnddev->ip, findVendorByMAC (known_ips, currEnddev->station_mac));
    i = getWord (currEnddev->first_time_seen, buffer, i, lSize);
    if (keepDate) strcpy (currEnddev->first_time_seen, first_time_seen);
    i = getWord (currEnddev->last_time_seen, buffer, i, lSize);
    if (!lastFile) strcpy(currEnddev->prev_last_time_seen, currEnddev->last_time_seen);
    i = getWord (power, buffer, i, lSize);
    currEnddev->oldPower = 0;
    if (currEnddev->old) currEnddev->oldPower = currEnddev->power;
    currEnddev->power = atoi(power);
    i = getWord (currEnddev->packets, buffer, i, lSize);
    i = getWord (currEnddev->bssid, buffer, i, lSize);
    if (strcmp (currEnddev->bssid, "(not associated)") != 0) {
      currAp = findApByBSSID (firstAp, currEnddev->bssid);
      if (currAp != NULL) {
        strcpy(currEnddev->essid, currAp->essid);
      } else {
        strcpy(currEnddev->essid, "");
      }
    } else {
      strcpy(currEnddev->essid, "");
    }
    strcpy (currEnddev->fileName, fileName);
    memcpy(&(currEnddev->prvtime2), &(currEnddev->time2), sizeof(datetime));
    sscanf (currEnddev->first_time_seen, "%d-%d-%d %d:%d:%d",
      &(currEnddev->time1.year),
      &(currEnddev->time1.month),
      &(currEnddev->time1.day),
      &(currEnddev->time1.hour),
      &(currEnddev->time1.minute),
      &(currEnddev->time1.second));
    sscanf (currEnddev->last_time_seen, "%d-%d-%d %d:%d:%d",
      &(currEnddev->time2.year),
      &(currEnddev->time2.month),
      &(currEnddev->time2.day),
      &(currEnddev->time2.hour),
      &(currEnddev->time2.minute),
      &(currEnddev->time2.second));
    if (currEnddev->power > currEnddev->maxPwrLevel && currEnddev->power < -1) {
      currEnddev->maxPwrLevel = currEnddev->power;
      strcpy(currEnddev->maxPwrTime, currEnddev->last_time_seen);
    }
    if (strcmp(currEnddev->maxPwrTime, "") == 0) strcpy(currEnddev->maxPwrTime, currEnddev->last_time_seen);
    // Skip leading whitespace
    while (i < lSize && (buffer[i] == ' ' || buffer[i] == '\t')) i++;

    // Grab the whole list of ESSIDs
    j = 0;
    while (i < lSize-1 && j < 253) {
      if (buffer[i] == '\r' && buffer[i+1] == '\n') {
        i += 2;
        break;
      }
      if (buffer[i] == '\n') {
        i++;
        break;
      }
      currEnddev->probed_essids[j] = buffer[i];
      i++; j++;
    }
    currEnddev->probed_essids[j] = '\0';
    if (verbosity >= 2) printf("added sta: %s\n", currEnddev->station_mac);
  }

//  fclose(pFile);
  free (buffer);

//  printf("Finished reading %s\n", fileName);  // Debug
  dset.s = firstAp;
  dset.e = firstEnddev;
  return dset;
}

int main (int argc, char **argv) {
  int i, lastFile, showAPs, showEnddevs;
  ap *firstAp = NULL;
  enddev *firstEnddev = NULL;
  gps *gps1 = NULL;
  devset dset;
/*
  FILE *csvFile = NULL;
  FILE *textFile = NULL;
  FILE *htmlFile = NULL;
 */
  FILE *tmpFile = NULL;
  char *fileToMonitor = NULL;
  char *filePrefix = NULL;
  char *gpsFile = NULL;
  char buffer[256];
//  int continuous = 0; //boolean

  // Set the default values
  onlyAddCommon = 0;
  onlyAddNew = 0;
  onlyAddOld = 0;
  deltaSpecified = 0;
  numInputFiles = 0;
  showAPs = 1;
  showEnddevs = 1;
  minPower = -100;
  maxPower = 0;
  minPowerDelta = -1;
  text_brief = 0;
  verbosity = 0;
  ap_count = 0;
  sta_count = 0;

  if (argc < 2) {
    printf ("Usage: %s [options] -w prefix file1 [file2] [file3]...[-l] [file n]\n", argv[0]);
    printf ("-a only show APs\n");
    printf ("-b print brief text in text mode\n");
    printf ("-e only show end devices\n");
//    printf ("-c specifies a csv file to output to\n");
//    printf ("-t specifies a text file to output to\n");
    printf ("-to prints text to stdout (cannot be used with -t)\n");
//    printf ("-h specifies a html file to output to\n");
    printf ("-g [file] specifies a GPS input file\n");
    printf ("-i [file] specifies a CSV file of known IP addresses\n");
    printf ("-l specifies the last file (must be the last file specified)\n");
    printf ("-k [file] specifies a CSV file of known MAC addresses\n");
    printf ("-m only show APs and Stations in the file specified with -k\n");
    printf ("-d [delta] only shows devices whose power is stronger than before by [delta]\n");
    printf ("-n only shows APs and Stations that are new in the last file\n");
    printf ("-o only shows APs and Stations that are not new in the last file\n");
    printf ("-p [power] only shows APs and Stations with power greater than [power]\n");
    printf ("-P [power] only shows APs and Stations with power less than [power]\n");
    printf ("-v verbose output\n");
    printf ("-vv very verbose output\n");
    printf ("-w [prefix] specifies output file prefix\n");
    return 1;
  }

  firstAp = NULL;
  firstEnddev = NULL;

  tmpFile = fopen("/usr/share/aircrack-ng/airodump-ng-oui.txt", "r");
  if (tmpFile) {
    fclose(tmpFile);
    readMacDB ("/usr/share/aircrack-ng/airodump-ng-oui.txt");
//    printf("reading /usr/share/aircrack-ng/airodump-ng-oui.txt\n");
  } else if (tmpFile = fopen("/etc/aircrack-ng/airodump-ng-oui.txt", "r")) {
    fclose(tmpFile);
    readMacDB ("/etc/aircrack-ng/airodump-ng-oui.txt");
//    printf("reading /etc/aircrack-ng/airodump-ng-oui.txt\n");
  }
  for (i = 1; i < argc; i++) {
/*
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-C") == 0) {
      i++;
      if (i >= argc) {
        printf ("-c requires that you specify an output csv file.\n");
        exit(1);
      }
      csvFile = fopen(argv[i], "w");
      if (csvFile == NULL) {
        printf ("Error opening CSV file: %s\n", argv[i]);
        exit(1);
      }
      continue;
    }
*/
/*
    if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "-T") == 0) {
      i++;
      if (i >= argc) {
        printf ("-t requires that you specify an output text file.\n");
        exit(1);
      }
      textFile = fopen(argv[i], "w");
      if (textFile == NULL) {
        printf ("Error opening text file: %s\n", argv[i]);
        exit(1);
      }
      continue;
    }
*/
    if (strcmp(argv[i], "-to") == 0 || strcmp(argv[i], "-TO") == 0) {
      if (textFile != NULL) {
        printf ("Error: -to cannot be used with -t\n");
        exit(1);
      }
      textFile = stdout;
      continue;
    }
/*
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-H") == 0) {
      i++;
      if (i >= argc) {
        printf ("-h requires that you specify an output text file.\n");
        exit(1);
      }
      htmlFile = fopen(argv[i], "w");
      if (htmlFile == NULL) {
        printf ("Error opening html file: %s\n", argv[i]);
        exit(1);
      }
      continue;
    }
*/
    if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "-A") == 0) {
      showEnddevs = 0;
      continue;
    }
    if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "-B") == 0) {
      text_brief = 1;
      continue;
    }
    if (strcmp(argv[i], "-d") == 0) {
      i++;
      if (i >= argc) {
        printf ("-d requires that you specify a minimum delta power level.\n");
        exit(1);
      }
      deltaSpecified = 1;
      minPowerDelta = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "-E") == 0) {
      showAPs = 0;
      continue;
    }
    if (strcmp(argv[i], "-g") == 0) {
      i++;
      if (i >= argc) {
        printf ("-g requires that you specify a GPS file.\n");
        continue;
      }
      gpsFile = argv[i];
      continue;
    }
    if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-I") == 0) {
      i++;
      if (i >= argc) {
        printf ("-i requires that you specify a MAC/IP address file.\n");
        exit(1);
      }
      readKnownIPs(argv[i]);

      continue;
    }
    if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "-K") == 0) {
      i++;
      if (i >= argc) {
        printf ("-k requires that you specify a MAC address/hostname file.\n");
        exit(1);
      }
      if (verbosity) printf ("Reading known MACs.\n");
      readKnownMacs(argv[i]);

      continue;
    }
    if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-M") == 0) {
      onlyShowKnown = 1;
      continue;
    }
    if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "-N") == 0) {
      onlyAddNew = 1;
      continue;
    }
    if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "-O") == 0) {
      onlyAddOld = 1;
      continue;
    }
    if (strcmp(argv[i], "-p") == 0) {
      i++;
      if (i >= argc) {
        printf ("-p requires that you specify a minimum power level.\n");
        exit(1);
      }
      minPower = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-P") == 0) {
      i++;
      if (i >= argc) {
        printf ("-P requires that you specify a maximum power level.\n");
        exit(1);
      }
      maxPower = atoi(argv[i]);
      continue;
    }
    if (strcmp(argv[i], "-v") == 0) {
      verbosity = 1;
      continue;
    }
    if (strcmp(argv[i], "-vv") == 0) {
      verbosity = 2;
      continue;
    }
    if (strcmp(argv[i], "-w") == 0) {
      i++;
      if (i >= argc) {
        printf ("-w requires that you specify an output prefix.\n");
        continue;
      }
      filePrefix = argv[i];
      continue;
    }
    // Note the lack of a continue statement after -l - this option must be last
    lastFile = 0;
    if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-L") == 0) {
      lastFile = 1;
      i++;
      if (i >= argc) {
        printf ("-l requires that you specify an input csv file.\n");
        exit(1);
      }
      fileToMonitor = argv[i];
    }
    if (verbosity) printf ("Reading CSV file: %s\n", argv[i]);
    dset = readCSVFile (argv[i], firstAp, firstEnddev, lastFile);
    firstAp = dset.s;
    firstEnddev = dset.e;
    numInputFiles++;
    if (verbosity >= 2) printf ("Finished reading CSV file.\n");
  }

  // Check for show stoppers
  if (numInputFiles == 0) {
    printf ("Error: no input files specified.\n");
    exit(1);
  }
  if (filePrefix == NULL) {
    printf ("Please specify an output prefix (-w option).\n");
    exit(1);
  }

  // Print the power level files
  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, "-appower.csv");
  if (verbosity) printf ("Opening file: %s\n", buffer);
  tmpFile = fopen(buffer, "r");
  if (tmpFile) {
    readAPPowerFromFile (firstAp, tmpFile);
    fclose (tmpFile);
  }
  tmpFile = fopen(buffer, "w");
  printAPPowerToFileRec (firstAp, tmpFile);
  fclose(tmpFile);

  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, "-stapower.csv");
  if (verbosity) printf ("Opening file: %s\n", buffer);
  tmpFile = fopen(buffer, "r");
  if (tmpFile) {
    readEnddevPowerFromFile (firstEnddev, tmpFile);
    fclose (tmpFile);
  }
  tmpFile = fopen(buffer, "w");
  printEndDevicesPowerToFileRec (firstEnddev, tmpFile);
  fclose(tmpFile);

  if (gpsFile) tmpFile = fopen(gpsFile, "r");
  if (gpsFile && tmpFile) {
    if (verbosity) printf ("Opening file: %s\n", gpsFile);
    gps1 = readGPSFile(firstAp, firstEnddev, tmpFile);
    addGPSInfo (firstAp, firstEnddev, gps1);
    free_gps(gps1);
  }

//  csvFile = htmlFile = kmlFile = NULL;

  if (textFile != stdout) {
    strcpy (buffer, "");
    strcat (buffer, filePrefix);
    strcat (buffer, ".txt");
    if (verbosity) printf ("Opening %s\n", buffer);
    textFile = fopen(buffer, "w");
  }

  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, ".csv");
  if (verbosity) printf ("Opening %s\n", buffer);
  csvFile = fopen(buffer, "w");

  strcpy (buffer, "");
  strcat (buffer, filePrefix);
  strcat (buffer, ".html");
  if (verbosity) printf ("Opening %s\n", buffer);
  htmlFile = fopen(buffer, "w");

  if (gpsFile) {
    strcpy (buffer, "");
    strcat (buffer, filePrefix);
    strcat (buffer, ".kml");
    if (verbosity) printf ("Opening %s\n", buffer);
    kmlFile = fopen (buffer, "w");
  }

/*
  if (textFile != NULL) {
    if (showAPs) printAPsToFileText (firstAp, textFile);
    if (showEnddevs) printEndDevicesToFileText (firstEnddev, textFile);
    if (textFile != stdout) fclose (textFile);
  }
*/

  if (csvFile && htmlFile && textFile) {
    if (kmlFile) fprintf (kmlFile, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\r\n<Document>\r\n");
    if (showAPs) {
      fprintf (csvFile, "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
      "Power, # beacons, # IV, LAN IP, ID-Length, ESSID, Key%s", CRLF);
      fprintf (htmlFile, "<html>%s<head></head><body>%s<table border=\"1\">%s", CRLF, CRLF, CRLF);
      fprintf (htmlFile, "<tr><td>BSSID</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>Prev time seen</td><td>channel</td><td>Speed</td><td>Privacy</td><td>Cipher</td><td>Authentication</td>"
        "<td>Power</td><td># beacons</td><td># IV</td><td>LAN IP</td><td>ID-Length</td><td>ESSID</td><td>Key</td><td>Description</td><td>IP Address</td></tr>%s", CRLF);

      if (verbosity) printf ("Printing APs to files\n");
      printAPsToFileRec (firstAp);
    }
    if (showEnddevs) {
      fprintf (csvFile, "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs%s", CRLF);
      fprintf (htmlFile, "</table><table border=\"1\"><tr><td>Station MAC</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>Prev time seen</td><td>Power</td><td># packets</td><td>BSSID</td>"
        "<td>ESSID</td><td>Probes</td><td>Description</td><td>IP Address</td></tr>%s", CRLF);
      if (verbosity) printf ("Printing Stations to files\n");
      printEndDevicesToFileRec (firstEnddev);
    }
    fprintf (htmlFile, "</table>%s</body>%s</html>", CRLF, CRLF);
    if (kmlFile) {
      fprintf (kmlFile, "</Document>\r\n</kml>\r\n");
      fclose (kmlFile);
    }
    fclose (csvFile);
    fclose (htmlFile);
    fclose (textFile);
    if (verbosity) printf ("Closed files\n");
  }
/*
  if (htmlFile != NULL) {
    if (showAPs) {
      fprintf (htmlFile, "<html>%s<head></head><body>%s<table border=\"1\">%s", CRLF, CRLF, CRLF);
      fprintf (htmlFile, "<tr><td>BSSID</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>channel</td><td>Speed</td><td>Privacy</td><td>Cipher</td><td>Authentication</td>", CRLF);
      fprintf (htmlFile, "<td>Power</td><td># beacons</td><td># IV</td><td>LAN IP</td><td>ID-Length</td><td>ESSID</td><td>Key</td></tr>%s", CRLF);
      printAPsToFileHTML (firstAp, htmlFile);
      fprintf (htmlFile, "</table>%s", CRLF);
    }
    if (showEnddevs) {
      fprintf (htmlFile, "<table border=\"1\">%s", CRLF);
      fprintf (htmlFile, "<tr><td>Station MAC</td><td>Vendor</td><td>First time seen</td><td>Last time seen</td><td>Power</td><td># packets</td><td>BSSID</td><td>ESSID</td><td>Probes</td></tr>%s", CRLF);
      printEndDevicesToFileHTML (firstEnddev, htmlFile);
      fprintf (htmlFile, "</table>%s</body>%s</html>", CRLF, CRLF, CRLF);
    }
    fclose (htmlFile);
  }
*/
/*
  if (continuous && fileToMonitor == NULL) {
    printf ("Error, last file not specified.\n");
    return 1;
  }
  while (continuous) {
    dset = readCSVFile (fileToMonitor, firstAp, firstEnddev, lastFile);
    firstAp = dset.s;
    firstEnddev = dset.e;
    if (showAPs) printAPsToFileText (firstAp, stdout);
    if (showEnddevs) printEndDevicesToFileText (firstEnddev, stdout);
    sleep(3);
  }
*/
  free_ap(firstAp);
  free_enddev(firstEnddev);

  return 0;
}

