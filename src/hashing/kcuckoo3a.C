// K-ary cuckoo hashing (c) 2002-2003 by Peter Sanders
// this is a simple implementation for the purposes
// of measuring the performance of cuckoo hashing in abstract
// terms (number of probes per insert, storage efficiency)
// usage: compile using g++ or another ISO C++ compiler
// a.out <K> <n> <r> <repeat> <seed for rng>
// there is also a constant tMax that defines the maximum number
// of trials for an insertion
// allocates space for n elements in K subtables, and repeats
// the follwing measurements repeat time:
// - find a hash function by filling full lookup tables
//   with pseudo-random numbers.
// - insert elements i=0..n-1 into the table until this fails 
//   for the first time. (The cost of these insertions is not
//   measured.)
//   Every n/r successfully inserted elements, the follwing
//   measurement is repeated n/r times:
//   * a random element i2 is removed
//   * the hash table entries for i2 are filled with new random values
//   * i2 is reinserted. 
//   Note that this is equivalent to removing a random element
//   inserting a new element that 
//   has never been in the table before.
// The output is a table that gives
// - x the number of elements in the table at each measuremnt interval
// - the average number of probes for an insertion during the measruements
//   for the given number of inserted elements
// - K
// - n
// - repeat
// - seed
#define DEBUGLEVEL 1
#include <iostream>
#include <stdlib.h>
#include "util.h"
#include "mt-real.c"
#include <assert.h>

#define split 1


using namespace std;
const int tMax = 10000; // max number of random walk trials
int K; // number of probes
int n; // number of elements
int m; // number of elements per table
int **hash;  // K times n array
int **table; // K times m array


// generate random int in 0..x-1
inline int rand0K(int x) { return int(genrand()*x); }


// insert element i into table
// return value:
// -1 failure
// otherwise number of hash function evaluation
int insert(int i) {
  int forbidden = -1;
  int j = rand0K(K);
  for (int t = 1;  t <= tMax;  t++) {
    int p    = hash [j][i];
    int newI = table[j][p];
    table[j][p] = i; // play the cuckoo
    if (newI == -1) return t; // done
    forbidden = j;
    i = newI; // find new home for cuckoo victim
    j = rand0K(K-1); 
    if (j == forbidden) j = K-1;
  }
  return tMax + 1; // insertion failed
}

// remove element i from the table
void remove(int i) {
  for (int j = 0;  j < K;  j++) {
    int p = hash[j][i];
    if (table[j][p] == i) {
      table[j][p] = -1;
      return;
    }
  }
}

/*int main(int argc, char **argv) {
  int i, j;
  assert(argc == 6);
  K             = atoi(argv[1]); // number of probes
  n             = atoi(argv[2]); // number of elements
  //  double eps    = atof(argv[3]); // space slack
  m             = int(n/K + 0.5);
  int r         = atoi(argv[3]); // number of measured densities
  int step      = n/r;
  int repeat    = atoi(argv[4]); // how often to start from scratch
  int seed      = atoi(argv[5]);
  sgenrand(seed);
  cout << "# x tAvg(x) K N repeat seed" << endl;

  // allocate hash function and table
  // and an empty table 
  hash  = (int**) malloc(sizeof(int*) * K);
  table = (int**) malloc(sizeof(int*) * K);
  for (j = 0;  j < K;  j++) {
    hash [j] = new int[n];
    table[j] = new int[m];
  }

  // initialize statistics
  // sumT[i] is the average time for size i*step
  double *sumT = new double[r+1]; 
  int *cf = new int[r+1]; 
  for (int i = 0;  i < r;  i++) {
    sumT[i] = 0;
    cf[i]   = 0;
  }

  // main loop
  for (int rep = 0;  rep < repeat;  rep++) {
    // init hash function and empty table
    for (j = 0;  j < K;  j++) {
      for (i = 0;  i < n;  i++) { hash [j][i] = rand0K(m); }
      for (i = 0;  i < m;  i++) { table[j][i] = -1; }
    }

    // fill table and keep measuring from time to time
    for (i = 0;  i < n;  i++) {
      if (insert(i) > tMax) break; // table is full
      if (((i+1) % step) == 0) { // measure in detail here
	for (int i1 = 0;  i1 < step;  i1++) {
	  // remove and reinsert a random element
	  int i2 = rand0K(i);
	  remove(i2);
          for (j = 0;  j < K;  j++) hash[j][i2] = rand0K(m);
	  int t = insert(i2);
	  cf[i/step] += (t > tMax);
	  //cout << t << endl;
	  sumT[i/step] += t;
	}
      }
    }
  }
      
  for (int rep = 0;  rep < r;  rep++) {
    cout << rep*step + step << " "
	 << sumT[rep]/step/repeat << " " 
	 << K << " "
	 << n << " " 
	 << repeat << " "
	 << seed << " "
	 << cf[rep] << endl;
  }
}
*/
