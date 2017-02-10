/*
 * C++ Interface for the bch code by Roberto Trifiletti
 */


#ifndef TINY_COMMIT_ECC_H_
#define TINY_COMMIT_ECC_H_


//extern "C" {
  #include "bch.h"
//}

#include "typedefs.h"

//This class acts as a wrapper for invoking the BCH code
class ECC {
public:
  ECC();
  void Encode(uint8_t data[], uint32_t len, uint8_t checkbits[]);
  
  void PrintCodeParams(); 

  struct bch_control* bch_ctrl;
};

#endif /* TINY_COMMIT_ECC_H_ */
