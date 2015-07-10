ruby-insika
===========

A Ruby library/gem implementing the full TIM (Tax Identification Module) API of the INSIKA (Cryptographic Tamper-proofing of Electronic Cash Registers) project. See http://insika.de/en for more information.

Code maturity: Working alpha release without code documentation.

Code has been tested on Debian Jessie with a physical INSIKA TIM smartcard, but should work in Windows too since the only dependency is the `smartcard` Ruby gem, which is a raw FFI interface to function calls in `winSCard.dll` (Windows) and `libpcsclite1` (Debian-like Linux distros). Latter Linux library has the same function calls as the Windows library.

Installation
------------

This gem is not yet on rubygems.org. Development installs only by cloning this git repository.

Dependencies
------------

In Linux:

    apt-get install libpcsclite1
    bundle install
    
In Windows:

    bundle install
    
Examples
--------

The full TIM API has been implemented. See method calls and responses below.

    git clone {path_to_github_repo}
    cd ruby-insika
    
    irb
    load './lib/insika.rb'
    
    t = Insika::Tim.new
    => #<Insika::Tim:0x00000002878b90>
    
    t.open
    => #<Smartcard::PCSC::Card:0x00000002872470 @context=#<Smartcard::PCSC::Context:0x000000028728a8 @_handle=2115169342>, @sharing_mode=:exclusive, @_handle=964158434, @protocol=:t1, @send_pci=#<FFI::Library::Symbol name=g_rgSCardT1Pci address=0x007ff4ace37940>>
    
    t.select_tim_application
    => ["NO_ERROR", nil]
    
    t.get_data_tim_status
    => ["NO_ERROR", {:lifecycle=>:personalized}]
    
    t.activate("your_pin_here")
    => {:lifecycle=>:activated, :tax_payer_id=>"INSIKA_TEST_LEPR", :consecutive_number=>1, :sequence_reports=>1, :sequence_transaction_first=>0, :sequence_transaction_last=>0, :signature=>"TCGN-YFXB-YYKA-T3PL-KNJS-MBKZ-245R-KUZI-UDSG-GSXM-XB56-AMJ2-UF3E-FI4C-NZWZ-KFUG-T2DI-K2KI-GVJS-O===-"}
    
    t.get_data_tim_status
    => ["NO_ERROR", {:lifecycle=>:activated}]
    
    t.get_data_tim_status_extended
    => ["NO_ERROR", {:lifecycle=>:activated, :version=>"T.1.1.0", :tax_payer_id=>"INSIKA_TEST_LEPR", :consecutive_number=>1, :serial_number=>"01234567890123456789012345678901", :currency_code=>978, :date=>"2025-06", :sequence_transactions=>1, :sequence_reports=>2}]
    
    t.get_data_booked_months
    => ["NO_ERROR", {:date=>"2015-06", :months_with_turnover=>[1]}]
    
    t.read_certificate
    => ["NO_ERROR", "MIIDEzC....]

Next, load the variables `example1` and `example2` from `example.rb` into your Ruby console to test a transaction.

    t.transact(example1)
    => ["NO_ERROR", {:tax_payer_id=>"INSIKA_TEST_LEPR", :consecutive_number=>1, :sequence_transactions=>2, :signature=>"QUBU-UX65-PSPA-V6J2-ES66-L7SP-3IR2-T2TU-UOLA-CXCV-N7SR-2JGM-BUE7-AJ5H-ULUF-NQWL-EDSH-7AFZ-DBTU-M===-"}]
 

    t.report_unsigned
    => ["NO_ERROR", {:lifecycle=>:activated, :tax_payer_id=>"INSIKA_TEST_LEPR", :consecutive_number=>1, :sequence_reports=>2, :sequence_transaction_first=>1, :sequence_transaction_last=>2, :containers=>{:standard=>{:turnover=>89.82, :turnover_negative=>9.98, :turnover_vat_rate=>19.0}, :reduced1=>{:turnover=>9.44, :turnover_negative=>0.0, :turnover_vat_rate=>7.0}}}
    
    
    t.report_signed("blah")
    => ["NO_ERROR", {:lifecycle=>:activated, :tax_payer_id=>"INSIKA_TEST_LEPR", :consecutive_number=>1, :sequence_reports=>3, :sequence_transaction_first=>1, :sequence_transaction_last=>2, :containers=>{:standard=>{:turnover=>89.82, :turnover_negative=>9.98, :turnover_vat_rate=>19.0}, :reduced1=>{:turnover=>9.44, :turnover_negative=>0.0, :turnover_vat_rate=>7.0}}, :signature=>"LP4E-AGQ6-CQAM-MWQV-AY7H-PTXH-JTAD-YCHD-QTPN-CT77-BASL-E2NX-QCYH-O4A5-SLRU-CCAJ-KHKO-EW5G-K2MV-A===-"}]
    
    t.report_span("201507", "201508")
    => ["NO_ERROR", {:lifecycle=>:activated, :tax_payer_id=>"INSIKA_TEST_LEPR", :consecutive_number=>1, :sequence_reports=>3, :sequence_transaction_first=>1, :sequence_transaction_last=>2, :containers=>{:standard=>{:turnover=>89.82, :turnover_negative=>9.98, :turnover_vat_rate=>19.0}, :reduced1=>{:turnover=>9.44, :turnover_negative=>0.0, :turnover_vat_rate=>7.0}}}]
    
    t.hash("test")
    => ["NO_ERROR", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"]
    
    t.close
    => nil

    
    
Licence
----------------------

Copyright (C) 2015  Red (E) Tools Ltd. <office@thebigrede.net>

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