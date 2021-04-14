oqs-engine
======================

---

**NOTE: As of April 2021 we are no longer maintaining oqs-engine due to a lack of new contributors on this project. Our development on dynamic plugging algorithms into OpenSSL will focus on OpenSSL's provider interface via the [oqs-provider sub-project](https://github.com/open-quantum-safe/oqs-provider).**

---

oqs-engine is a C-based [OpenSSL ENGINE](https://github.com/openssl/openssl/blob/master/README.ENGINE) that enables the use of post-quantum digital signature algorithms.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
- [Quickstart](#quickstart)
  * [Linux](#linux)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**oqs-engine** is an OpenSSL ENGINE that provides pmeth (PKEY) and ameth (ASN1) operations for post-quantum digital signature algorithms supplied by liboqs. The engine also provides for dynamic assignment of openssl NIDs, which means updates/changes to the NIST algorithms supported by liboqs will be dynamically reflected by this ENGINE. oqs-engine aims to facilitate the integration of liboqs into generalised OpenSSL deployments.

Both liboqs and this ENGINE are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography. More information about the project can be found [here](https://openquantumsafe.org/).

## Status

The ENGINE requires OPENSSL 1.1.0g or later.

**We do not recommend using this in a production environment or to protect sensitive data.**

liboqs and this ENGINE are provided "as is", without warranty of any kind.  See the [LICENSE](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for the full disclaimer.

### Limitations and Security

As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying quantum-safe cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used by the ENGINE, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

## Quickstart

### Linux

1. Install dependencies:

	On Ubuntu:

		 apt install cmake gcc ninja-build libssl-dev doxygen

2. Get the source:

		git clone -b master https://github.com/open-quantum-safe/oqs-engine.git
		cd oqs-engine

	and build:

		mkdir build && cd build
		cmake -G"Ninja" ..
		ninja

By default, `cmake` looks for OpenSSL in `/usr`. If located elsewhere, the `-DOPENSSL_ROOT_DIR=<dir>` option can be passed to `cmake`, where `<dir>` specifies the directory in which `cmake` will look for OpenSSL.

All subsequent instructions assume we are in `build`.

3. The main build result is `lib/liboqse.so`, the OpenSSL ENGINE shared library.

4. Additionally, the `oqse_test` program is built in the `tests` directory. It can serve both for testing purposes and as a reference for using the ENGINE, and can be run either by:

- invoking `ninja run_tests`
- directly invocation of the program after setting the `OPENSSL_ENGINES` environment variable to point to `build/lib` directory so that the ENGINE can be found. i.e.:

		env OPENSSL_ENGINES = $(pwd)/lib ./tests/oqse_test

More information can be found in the [Wiki](https://github.com/open-quantum-safe/oqs-engine/wiki).

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this ENGINE include:

- John F Weston (Senetas Corporation)
- Goutam Tamvada (University of Waterloo)

## Acknowledgements

This engine was very much inspired by [libsoula](https://github.com/romen/libsuola/).

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.
We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, Cisco Systems, evolutionQ, Microsoft Research, and Senetas Corporation.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see [here](https://openquantumsafe.org/papers/SAC-SteMos16.pdf) and [here](https://openquantumsafe.org/papers/NISTPQC-CroPaqSte19.pdf) for funding acknowledgments.
