# PyScripts

A collection of Python 3 source code for simple python modules & scripts, written to be used as example programs.

Feel free to leave comments or send suggestions to dev.sagarbhat@gmail.com.

If you need help installing Python, visit https://installpython3.com/

About this Collection
=====================

When I'd started exploring python, the thing that definitely helped me to have a better grasp at the language was playing around with the source code of various small projects. The more simple and readable the program, the easier it becomes to get a hold of what's really happening and make adjustments as needed.

To help others down the same path, I'm creating a collection of these example programs which have minimum or no dependencies, aimed at being easy to copy and understand by beginners. These programs have the following constraints:

* They're short programs, with a soft limit of 256 lines of code and fit into a single source code file and don't need any installer. *This makes them easy to read and understand in one sitting. The shorter the better.*
* **Elegant** and **efficient** code is worthless in comparison to the code that is **easy to understand** and **readable**. *These programs are for education, not production. Standard best practices, like not using global variables, can be ignored to make it easier to understand. At some places I've suppressed linting exceptions as well, for the same reason.*
* All files are linted and functions have docstrings. *This is good documentation practice, but also enables the `help()` function to work in the interactive shell.*


Additional Guidelines
=====================

Additional guidelines include:

* None yet. I'll keep you updated.


Completed Programs in This Collection
=====================================

*1. AES-256 Encryption Decryption Suite* - A modular program that can be used as a script or imported as a module for it's various useful utility functions for AES-256 based encrption/decryption. (Requires click, pbkdf2 & pyaes)