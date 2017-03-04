This is intended to be a random password generator.

You tell it what you need from your password, and it will figure out
a scheme to generate an acceptable password.  It will tell you the
number of bits of entropy the scheme it came up with has, so you can be
sure of its strength.

Examples:

`password_generator --bits 80 --with words`

`password_generator --bits 80 --with ascii`

TODO: `password_generator --bits 80 --with lower,upper,number,symbol`

TODO: `password_generator --bits 40 --with lower,upper,number --max-length 16`

If no options are given, it is the same as running: `password_generator --bits 40 --with words`

Credits:

The word list was acquired from the Javascript at https://passwordcreator.org/
by Stephen Ostermiller.
