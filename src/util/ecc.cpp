#include "ecc.h"

ECC::ECC() {
  bch_ctrl = init_bch(CONFIG_BCH_CONST_M, CONFIG_BCH_CONST_T, 0);
}


void ECC::PrintCodeParams() {
  std::cout << "Code parameters: " << std::endl;
  std::cout << "m = " << bch_ctrl->m << std::endl;
  std::cout << "n = " << bch_ctrl->n << std::endl;
  std::cout << "t = " << bch_ctrl->t << std::endl;
  std::cout << "ecc_bits = " << bch_ctrl->ecc_bits << std::endl;
  std::cout << "ecc_bytes = " << bch_ctrl->ecc_bytes << std::endl;

}

//checkbits should be BCH_BYTES long and initialized to 0!
void ECC::Encode(uint8_t data[], uint32_t len, uint8_t checkbits[]) {
  encode_bch(bch_ctrl, data, len, checkbits);
}
