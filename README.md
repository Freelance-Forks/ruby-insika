Insika
=======================================================================

Installation
------------

    apt-get install libpcsclite1
    gem install insika
    

Testing
-------

irb
load './lib/insika.rb'
load './lib/insika/tim.rb'
t = Insika::Tim.new
t.open
t.select_tim_application
t.get_data_tim_status
t.get_data_tim_status_extended
t.get_data_booked_months
t.read_certificate
t.activate("pin")

t.transact(example1)
=> "c410494e53494b415f544553545f4c455052c50101cb01019e308a2a48586f393ceb7ed8c656c20b4a90bc6ecf515ad8c130d4664165f83e5e682ad36216ec7cdf1d280ffddbe9f94fb5"

t.verify_signature(example1, 1, "RIVE-QWDP-HE6O-W7WY-YZLM-EC2K-SC6G-5T2R-LLMM-CMGU-MZAW-L6B6-LZUC-VU3C-C3WH-ZXY5-FAH7-3W7J-7FH3-K===-")

t.report_unsigned
t.hash("test")
t.close


Application
----------------------

Insika is actively used in the production-quality Point of Sale products

[SALOR Retail](https://github.com/jasonknight/salor-retail)

and

[SALOR Hospitality](https://github.com/michaelfranzl/SalorHospitality)

and indirectly used by dozens of real stores daily, around the clock, around the world.


Contact
----------------------

Ask for support or additional features!

Red (E) Tools Ltd.

office@thebigrede.net

www.thebigrede.net


Licence
----------------------

Copyright (C) 2011-2013  Red (E) Tools Ltd. <office@thebigrede.net>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# PIN ACTIVATE DUMP

t.activate "342883"
["80", "42", "04", "00", "cd0420150709ce021449c306333432383833", "00"]
[INSIKA] Composed command: 8042040012cd0420150709ce021449c30633343238383300
[INSIKA] Sending: 8042040012cd0420150709ce021449c30633343238383300
[INSIKA] Result: c00103c410494e53494b415f544553545f4c455052c50101cc0101d20100d301009e30988cdc16e1c61409edeb5353260559d73b155328a0e4634aecb87be0313aa17642a3826e6d9516869e868569483553279000
[INSIKA] Parsed status NO_ERROR
=> "c00103c410494e53494b415f544553545f4c455052c50101cc0101d20100d301009e30988cdc16e1c61409edeb5353260559d73b155328a0e4634aecb87be0313aa17642a3826e6d9516869e86856948355327"

t.myparsetlv "c00103c410494e53494b415f544553545f4c455052c50101cc0101d20100d301009e30988cdc16e1c61409edeb5353260559d73b155328a0e4634aecb87be0313aa17642a3826e6d9516869e86856948355327".to_byte_s