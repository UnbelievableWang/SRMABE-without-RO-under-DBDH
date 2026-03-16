# SR-MABE Java Prototype

A Java prototype implementation of a **Server-aided Revocable Multi-Authority Attribute-Based Encryption (SR-MABE)** scheme with a standalone **MinSR** revocation module.

This project is organized in a modular way for clarity and debugging:

- `MinSR` is implemented as an independent class for binary-tree-based logical revocation.
- `SRMABE` invokes `MinSR` as a submodule and implements the main cryptographic workflow.
- `SRMABEDemo` provides a minimal runnable example for testing registration, path derivation, revocation, and the interaction between revocation state and transformation information generation.

## Overview

This repository contains a Java prototype of the construction described in our paper.

The implementation follows the high-level design below:

- Each authority maintains its own local `MinSR` state.
- User registration is mapped to a leaf in the authority-local binary tree.
- Public path labels are derived from the root-to-leaf path in the MinSR tree.
- Revocation is handled logically by disabling nodes and refreshing the epoch token.
- The `SRMABE` layer uses the `MinSR` path structure as the user-specific linkage mechanism.

The current implementation is intended as a **research prototype / debug-oriented reference implementation**, rather than a production-ready cryptographic library.

## Project Structure

```text
.
├── PP.java
├── MinSR.java
├── SRMABE.java
└── SRMABEDemo.java
## Dependency

This project depends on **JPBC 2.0.0** for bilinear pairing operations.

Please make sure the JPBC library is included in your Java project before compiling and running the code.  
In particular, the implementation relies on the pairing-related classes provided by JPBC for group element generation, exponentiation, and bilinear map evaluation.

The required dependency version is:

- **JPBC 2.0.0**

If you are using this project in an IDE such as IntelliJ IDEA or Eclipse, add the JPBC 2.0.0 JAR files to the project build path manually.

If you are managing dependencies with Maven, you may need to install the JPBC 2.0.0 JARs locally first, since JPBC is not always available in standard remote repositories.

Before running the demo, ensure that:

- the JPBC 2.0.0 library has been added correctly
- the pairing parameter files required by your `PP.java` implementation are available
- the project can successfully resolve JPBC classes such as pairing, field, and element types
