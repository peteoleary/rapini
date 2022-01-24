# Rapini

## Overview

Rapini is a REST API wrapper around the rabe library (https://github.com/Fraunhofer-AISEC/rabe)

I am using the project mostly as a personal introduction to Rust language and also to learn more about various attribute based encryption schemes.

As of January 2022, I am still working on implementing AC17. I will update this readme to mark my progress.

The project is very test-heavy on purpose as Rust tests serve as great example code. I use the local version of rabe calls to validate the REST equivalent calls.

There is a reference server implentation here https://rapini.herokuapp.com/. This server currently implements no login or authentication and probably never will.