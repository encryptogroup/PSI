/*
 * codewords.cpp
 *
 *  Created on: Oct 10, 2014
 *      Author: mzohner
 */


#include "codewords.h"

/*void readCodeWords(uint64_t** codewords) {
	uint32_t i, j, k;
	for(i = 0; i < m_nCodewords; i++) {
		for(j = 0; j < (m_nCWIntlen * sizeof(uint32_t)) / sizeof(uint64_t); j++) {
			codewords[i][j] = 0;
			for(k = 0; k < sizeof(uint64_t) / sizeof(uint32_t); k++) {
				codewords[i][j] |= (((REGISTER_SIZE) CODE_MATRIX[i][j*sizeof(REGISTER_SIZE) / sizeof(uint32_t)+k]) << (k * 8 * sizeof(uint32_t)));
				//cout << (hex) << CODE_MATRIX[i][j*2+k];
			}
		//	cout << (hex) << codewords[i][j] << ", ";
		}
		//cout << endl;
	}
}
*/
