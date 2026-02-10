/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "SerializationUtils.h"

void SerializationUtils::writeCiphertext(Ciphertext& cipher, string path) {
	fstream fout;
	fout.open(path, ios::binary|ios::out);
	long n = cipher.n;
	long logp = cipher.logp;
	long logq = cipher.logq;
	fout.write(reinterpret_cast<char*>(&n), sizeof(long));
	fout.write(reinterpret_cast<char*>(&logp), sizeof(long));
	fout.write(reinterpret_cast<char*>(&logq), sizeof(long));

	long np = ceil(((double)logq + 1)/8);
	ZZ q = conv<ZZ>(1) << logq;
	unsigned char* bytes = new unsigned char[np];
	for (long i = 0; i < N; ++i) {
		cipher.ax[i] %= q;
		BytesFromZZ(bytes, cipher.ax[i], np);
		fout.write(reinterpret_cast<char*>(bytes), np);
	}
	for (long i = 0; i < N; ++i) {
		cipher.bx[i] %= q;
		BytesFromZZ(bytes, cipher.bx[i], np);
		fout.write(reinterpret_cast<char*>(bytes), np);
	}
	fout.close();
}

Ciphertext* SerializationUtils::readCiphertext(string path) {
	long n, logp, logq;
	fstream fin;
	fin.open(path, ios::binary|ios::in);
	fin.read(reinterpret_cast<char*>(&n), sizeof(long));
	fin.read(reinterpret_cast<char*>(&logp), sizeof(long));
	fin.read(reinterpret_cast<char*>(&logq), sizeof(long));

	long np = ceil(((double)logq + 1)/8);
	unsigned char* bytes = new unsigned char[np];
    // 1. Allocate on Heap using 'new'
    Ciphertext* cipher = new Ciphertext(logp, logq, n); 
    
    for (long i = 0; i < N; ++i) {
        fin.read(reinterpret_cast<char*>(bytes), np);
        // 2. Use '->' instead of '.' to access members
        ZZFromBytes(cipher->ax[i], bytes, np); 
    }
    for (long i = 0; i < N; ++i) {
        fin.read(reinterpret_cast<char*>(bytes), np);
        // 3. Use '->' instead of '.'
        ZZFromBytes(cipher->bx[i], bytes, np); 
    }
    fin.close();
    
    // 4. Return the pointer directly (no '&')
    return cipher;
}

void SerializationUtils::writeKey(Key* key, string path) {
	fstream fout;
	fout.open(path, ios::binary|ios::out);
	fout.write(reinterpret_cast<char*>(key->rax), Nnprimes*sizeof(uint64_t));
	fout.write(reinterpret_cast<char*>(key->rbx), Nnprimes*sizeof(uint64_t));
	fout.close();
}

Key* SerializationUtils::readKey(string path) {
    // 1. Allocate on Heap
    Key* key = new Key(); 
    
    fstream fin;
    fin.open(path, ios::binary|ios::in);
    
    // 2. Use '->' instead of '.'
    fin.read(reinterpret_cast<char*>(key->rax), Nnprimes*sizeof(uint64_t));
    fin.read(reinterpret_cast<char*>(key->rbx), Nnprimes*sizeof(uint64_t));
    
    fin.close();
    
    // 3. Return the pointer directly
    return key; 
}

