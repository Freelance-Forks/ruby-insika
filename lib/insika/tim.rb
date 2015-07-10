# t.hash(Insika::Profile.hash(example1).to_byte_s) == Digest::SHA1.hexdigest(Insika::Profile.hash(example1).to_byte_s)

# Insika::Base32.encode(t.hash(Insika::Profile.hash(example1).to_byte_s).to_byte_s) == Insika::Base32.encode(Digest::SHA1.hexdigest(Insika::Profile.hash(example1).to_byte_s).to_byte_s)

# Digest::SHA1.hexdigest Insika::Profile.transaction_items_tlv(example1).to_byte_s
# Insika::Profile.transaction_items_hash(example1)
# Insika::Base32.encode Insika::Profile.transaction_items_hash(example1).to_byte_s
# => "5ef013f1a1f33b00fb18009bbc51638b364c6e28"

# Insika::Profile.transaction_tlv(example1)
example1 = {
  :item_designation_print_length => 16,
  :transaction => {
            :timestamp => Time.now, #Time.parse("2010-02-28 23:59"),
            :operator => "operator5",
            :currency_code => 978,
            :vat_not_included => false,
            :training => false,
            :containers => {
                            :standard => { # sending: only D8 - DB tags [1] 2.6.20
                                          :turnover => 44.91,
                                          :negative_turnover => 4.99,
                                          :vat_amount => 7.17,
                                          :vat_rate => 19,
                                          },
                            :reduced1 => {
                                          :turnover => 4.72,
                                          :negative_turnover => 0,
                                          :vat_amount => 0.31,
                                          :vat_rate => 7,
                                          },
                            # thirdparty etc.
#                             :third_party => {
#                                             :turnover => 0.0,
#                                             },
#                             :delivery_note => {
#                                             :turnover => 0.0,
#                                               }
                                 },
                   },
  :items => [
              { :quantity => 0.08,
                :unit => "kg",
                :designation => "Japan Sencha",
                :discount_surcharge => nil,
                :voucher => nil,
                :prices => {
                            :standard => nil,
                            :reduced1 => 4.72,
                            :reduced2 => nil,
                            :vat_free => nil,
                            :special1 => nil,
                            :special2 => nil,
                            }
              },
              { :quantity => 1,
                :unit => nil,
                :designation => "Teekanne Gusseisen",
                :discount_surcharge => nil,
                :voucher => nil,
                :prices => {
                            :standard => 49.90,
                            :reduced1 => nil,
                            :reduced2 => nil,
                            :vat_free => nil,
                            :special1 => nil,
                            :special2 => nil,
                            }
                },
              { :quantity => 1,
                :unit => nil,
                :designation => "10% Rabatt", # mistakenly translated in [1]
                :discount_surcharge => true,
                :voucher => nil,
                :prices => {
                            :standard => -4.99,
                            :reduced1 => nil,
                            :reduced2 => nil,
                            :vat_free => nil,
                            :special1 => nil,
                            :special2 => nil,
                            }
                },
             ]
  }

# Digest::SHA1.hexdigest Insika::Profile.transaction_items_tlv(example2).to_byte_s
# => "b45bfab30deebaba23b7f18d652d074f48f403a4"
example2 = {
  :item_designation_print_length => 16,
  :items => [
             { :quantity => 54.03,
               :unit => "l",
               :designation => "Diesel",
               :discount_surcharge => nil,
               :voucher => nil,
               :prices => {
                           :standard => 61.59,
                           :reduced1 => nil,
                           :reduced2 => nil,
                           :vat_free => nil,
                           :special1 => nil,
                           :special2 => nil,
                           }
               },
             ]
  }

module Insika
  
  module SalorHospitality
    def to_insika
      puts "to insika #{ self.id }"
    end
  end
  
  module HexInteger
    def to_hex_s(words=nil)
      num = self
      num += 0.001 # to prevent -Inf in log2
      words = 2 + 2 * (Math.log2(num) / 8).floor unless words
      "%0#{ words }x" % self
    end
    
    # Unsigned Binary Coded Decimal
    def to_ubcd_s
      str = self.abs.to_s
      result = ""
      result = "0" if str.length % 2 == 1
      result += str
    end
    
    # Signed Binary Coded Decimal
    def to_sbcd_s
      str = self.abs.to_s
      result = ""
      result = "0" if str.length % 2 == 0
      result += str
      result += self >= 0 ? "c" : "d"
    end
  end
  
  module HexString
    
    def sbcd_hex_to_i
      sign = self[-1] == "c" ? 1 : -1
      self[0..-2].to_i * sign
    end
    
    def ubcd_hex_to_i
      self.to_i
    end
    
    def to_ubcd_hex
      self
    end
    
    def to_byte_s
      str = self.gsub /\s+/, ''
      raise "Need even number of hex digits" unless str.size % 2 == 0
      raise "Non-hex character provided" if str =~ /[^0-9A-Fa-f]/
      [str].pack 'H*'
    end
    
    def to_hex_s
      str = self.unpack('H*').first
    end
    
    def to_i_from_hex
      self.gsub(/\s+/, '').to_i(16)
    end

    def hex_length
      self.gsub(/\s+/, '').length / 2
    end
    
    def group_hex
      self.gsub(/(..)/, '\1 ')
    end
  end
  
  
  module Base32
    # https://github.com/stesla/base32/blob/master/lib/base32.rb
    # http://www.simplycalc.com/base32-encode.php
    TABLE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.freeze
    
    class Chunk
      def initialize(bytes)
        @bytes = bytes
      end
      
      def decode
        bytes = @bytes.take_while {|c| c != 61} # strip padding
        n = (bytes.length * 5.0 / 8.0).floor
        p = bytes.length < 8 ? 5 - (n * 8) % 5 : 0
        c = bytes.inject(0) {|m,o| (m << 5) + Base32.table.index(o.chr)} >> p
        (0..n-1).to_a.reverse.collect {|i| ((c >> i * 8) & 0xff).chr}
      end
      
      def encode
        n = (@bytes.length * 8.0 / 5.0).ceil
        p = n < 8 ? 5 - (@bytes.length * 8) % 5 : 0
        c = @bytes.inject(0) {|m,o| (m << 8) + o} << p
        [(0..n-1).to_a.reverse.collect {|i| Base32.table[(c >> i * 5) & 0x1f].chr},
         ("=" * (8-n))]
      end
    end
    
    def self.chunks(str, size)
      result = []
      bytes = str.bytes
      while bytes.any? do
        result << Chunk.new(bytes.take(size))
        bytes = bytes.drop(size)
      end
      result
    end
    
    def self.encode(str)
      groups = chunks(str, 5).collect(&:encode).flatten.join
    end
    
    def self.decode(str)
      chunks(str.gsub(/[^#{ TABLE }]/, ""), 8).collect(&:decode).flatten.join
    end
    
    def self.table=(table)
      raise ArgumentError, "Table must have 32 unique characters" unless self.table_valid?(table)
      @table = table
    end
    
    def self.table
      @table || TABLE
    end
    
    def self.table_valid?(table)
      table.bytes.to_a.size == 32 && table.bytes.to_a.uniq.size == 32
    end
  end
  

  
  module Profile

    def self.transaction_tlv(data, verify=false)
      tdata = data[:transaction]
      
      tlv = ""
      # Date
      date_str = tdata[:timestamp].strftime("%Y%m%d")
      date_tlv = Util.compose_tlv("cd", date_str)
      tlv += date_tlv
      
      # Time
      time_str = tdata[:timestamp].strftime("%H%M")
      time_tlv = Util.compose_tlv("ce", time_str)
      tlv += time_tlv
      
      # Operator name
      op_tlv =  Util.compose_tlv("c6", tdata[:operator].to_hex_s)
      tlv += op_tlv
      
      # transaction items hash
      hash_tlv = Util.compose_tlv("c7", transaction_items_hash(data))
      tlv += hash_tlv
      
      unless verify
        # currency code
        currency_tlv = Util.compose_tlv("c8", tdata[:currency_code].to_hex_s)
        tlv += currency_tlv
      end
      
      if tdata[:vat_not_included]
        flag_vat_not_included_tlv = Util.compose_tlv("c9")
        tlv += flag_vat_not_included_tlv
      end
      
      if tdata[:training]
        flag_training_tlv = Util.compose_tlv("ca")
        tlv += flag_training_tlv
      end
      
      if verify
        # Sequence number of transaction
        sequence_tlv = Util.compose_tlv("cb", tdata[:transaction_sequence_number].to_hex_s)
        tlv += sequence_tlv
      end
      
      # containers
      container_names = [:standard, :reduced1, :reduced2, :vat_free, :special1, :special2, :third_party, :delivery_note]
      container_names.each_with_index do |cname, idx|
        next unless tdata[:containers].has_key? cname
        
        container_tlv = ""
        vals = tdata[:containers][cname]
        
        next if vals[:turnover].zero? and vals[:negative_turnover].zero? # [1] 2.6.20
        
        # 1st: turnover
        unless vals[:turnover].zero?
          turnover = Integer(100 * vals[:turnover]).to_sbcd_s
          turnover_tlv = Util.compose_tlv("d8", turnover)
          container_tlv += turnover_tlv
        end
        
        unless (cname == :third_party or cname == :delivery_note) and verify
          # 2nd: negative turnover
          unless vals[:negative_turnover].zero?
            negative_turnover = Integer(100 * vals[:negative_turnover]).to_sbcd_s
            negative_turnover_tlv = Util.compose_tlv("d9", negative_turnover)
            container_tlv += negative_turnover_tlv
          end
          
          # 3nd: VAT amount
          unless vals[:vat_amount].zero?
            vat_amount = Integer(100 * vals[:vat_amount]).to_sbcd_s
            vat_amount_tlv = Util.compose_tlv("da", vat_amount)
            container_tlv += vat_amount_tlv
          end
          
          # 4nd: VAT rate
          vat_rate = Integer(100 * vals[:vat_rate]).to_ubcd_s
          vat_rate_tlv = Util.compose_tlv("db", vat_rate)
          container_tlv += vat_rate_tlv
        end
        
        if verify
          signature_tlv = Util.compose_tlv("9e", Base32.decode(tdata[:signature]).to_hex_s)
          tlv += signature_tlv
        end
        
        tlv += Util.compose_tlv("e#{ idx + 1 }", container_tlv)
      end

      return tlv
    end
    
    def self.transaction_items_hash(data)
      tlv = transaction_items_tlv(data)
      sha1 = Digest::SHA1.hexdigest(tlv.to_byte_s)
    end
    
    def self.transaction_items_tlv(data)
      tlv = ""
      data[:items].each do |ti|
        item_tlv = ""
        
        # 1st: Quantity / number
        item_tlv += Util.compose_tlv("a0", ti[:quantity].to_s.to_hex_s)
        
        # 2nd: Unit of quantity
        # TODO: check unit
        if ti[:unit]
          item_tlv += Util.compose_tlv("a1", ti[:unit].to_hex_s)
        end
        
        # 3rd: Commercial designation
        designation = Util.subst_chars(
          ti[:designation],
          data[:item_designation_print_length]
        ).to_hex_s
        item_tlv += Util.compose_tlv("a2", designation)
        
        # 4th: Discount / Surcharge
        if ti[:discount_surcharge] == true
          item_tlv += Util.compose_tlv("aa")
        end
        
        # 5th: Voucher
        if ti[:voucher] == true
          item_tlv += Util.compose_tlv("ab")
        end
        
        # 6th: Prices 1-6
        ti[:prices].each_with_index do |keyval, idx|
          val = keyval[1]
          next if val == nil
          tag = "b#{ idx + 1 }"
          value = Integer(100 * val).to_sbcd_s
          item_tlv += Util.compose_tlv(tag, value)
        end
        
        tlv += item_tlv
      end
      return tlv
    end
  end
  
  module Util
    # takes human-readable hex strings
    def self.compose_tlv(tag, value=nil)
      res = ""
      res += tag
      if value
        len = value.hex_length.to_hex_s
        res += len
        res += value
      else
        len = "00"
        res += len
      end
    end
    
    
    # Composes a command
    # @param cla [String] The class word. Two-byte human-readable hex string.
    # @param ins [String] The instruction word. Two-byte human-readable hex string.
    # @param p1 [String] The P1 parameter. Two-byte human-readable hex string.
    # @param p2 [String] The P2 parameter. Two-byte human-readable hex string.
    # @param data [String] Payload data. Arbitrary length human-readable hex string.
    # @param le [String] Expected response length. Two-byte human-readable hex string.
    # @return [String] A byte string
    def self.compose_command(cla, ins, p1, p2, data, le)
      puts "#{ [cla, ins, p1, p2, data, le] }"
      str = ""
      str += cla
      str += ins
      str += p1
      str += p2 if p2
      str += data.hex_length.to_hex_s if data
      str += data if data
      str += le if le
      str.gsub!(/\s+/, "")
      Insika.log("Composed command: #{ str }")
      str.to_byte_s
    end
    
    # [1] 6.2
    # Test: puts Util.subst_chars("Käsesemmel mit Pommes", 12)
    def self.subst_chars(str, item_designation_print_length)
      # 1. limit to actually used printing length
      result1 = str[0..item_designation_print_length]
      
      # 2. Omit non printable characters < 0x21 (33) and >= 0x7F (127)
      result2 = ""
      result1.length.times do |i|
        char = result1[i]
        dec = char.ord
        result2 += result1[i] unless dec < 33 or dec == 127
      end
      
      # 3. lower case
      result3 = result2.downcase
      
      # 4. and 5. substitute not permitted chars with #
      result5 = result3.gsub(/[^0-9a-z]/, "#")
      
      # 6. cut off after 16 characters
      result6 = result5[0..15]
      
      return result6
    end
    
  end
  #Insika::Profile.blah

  
  class Tim

    def initialize
      #p = Insika::Profile.new
      #Insika::Profile.blah = 3 #instance_methods
      
      #Insika::Profile.hash(items)
    end
    
    def open
      Insika.log "Opening card"
      @context = Smartcard::PCSC::Context.new
      readers = @context.readers
      @reader = readers.first
      @card = Smartcard::PCSC::Card.new @context, @reader
    end
    
    def close
      @card.disconnect
      @context.release
      Insika.log "Closed card"
    end
    
    def select_tim_application
      aid = Insika.rid + Insika.pix # [1] p. 29
      cmd = Util.compose_command("00", "a4", "04", "0c", aid, nil)
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
    end
    
    def read_certificate
      # SELECT FILE
      cmd = Util.compose_command("00", "a4", "00", "0c", "11 10", nil)
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      raise "SELECT FILE command not successful" unless stat == "NO_ERROR"
      
      # READ CERTIFICATE
      chunk_size = 128
      chunk_size_hex = chunk_size.to_hex_s
      cert = ""
      cert_length = 0
      0.upto(6) do |i|
        Insika.log "CERT LOOP #{ i }"
        offset = (i * chunk_size).to_hex_s(4)
        p1 = offset[0..1]
        p2 = offset[2..3]
        cmd = Util.compose_command("00", "b0", p1, p2, nil, chunk_size_hex)
        resp = transmit(cmd)
        stat = parse_status(resp[-2..-1])
        if i == 0
          cert_length = 4 + resp[2..3].gsub(" ", "").to_hex_s.to_i_from_hex
          Insika.log "CERT LENGTH IS #{ resp[2..3].inspect } #{ cert_length }"
        end
        cert += resp[0..-3]
      end
      cert = cert[0..cert_length - 1]
      Insika.log "CERTIFICATE IS #{ cert.to_hex_s }"
      #openssl x509 -text -noout -inform DER -in cert.der
      File.open("cert.der", 'wb') { |f| f.write(cert) }
      Base64.encode64(cert)
    end
    
    def get_data_tim_status
      cmd = Util.compose_command("00", "CA", "01", "F0", nil, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("TIM status result: #{ result }")
    end
    
    def get_data_tim_status_extended
      cmd = Util.compose_command("00", "CA", "01", "F1", nil, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("TIM status extended result: #{ result }")
    end
    
    def get_data_booked_months
      cmd = Util.compose_command("00", "CA", "01", "F2", nil, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("TIM booked months result: #{ result }")
    end
    
    def hash(byte_str)
      data = byte_str.to_hex_s
      cmd = Util.compose_command("00", "2A", "90", "80", data, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      #Insika.log("Hash result: #{ resp[0..-3].to_hex_s }")
      return resp[0..-3].to_hex_s
    end
    
    def transact(data)
      transaction_tlv = Profile::transaction_tlv(data, false)
      cmd = Util.compose_command("80", "40", "00", "00", transaction_tlv, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("transact result: #{ result }")
      return result
    end
    
    def verify_signature(data, sequence, signature)
      verify_data = data
      verify_data[:transaction][:transaction_sequence_number] = sequence
      verify_data[:transaction][:signature] = signature
      verify_transaction_tlv = Profile::transaction_tlv(verify_data, true)
      
      cmd = Util.compose_command("80", "44", "00", "00", verify_transaction_tlv, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("transact verify result: #{ result }")
      return result
    end
    
    def report_unsigned
      tlv = ""
      
      date_tlv = Util.compose_tlv("cd", Time.now.strftime("%Y%m%d").to_ubcd_hex)
      tlv += date_tlv
      
      time_tlv = Util.compose_tlv("ce", Time.now.strftime("%H%M").to_ubcd_hex)
      tlv += time_tlv

      cmd = Util.compose_command("80", "42", "02", "00", tlv, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("report unsigned result: #{ result }")
      return result
    end
    
    def report_signed(hash)
      tlv = ""
      
      date_tlv = Util.compose_tlv("cd", Time.now.strftime("%Y%m%d").to_ubcd_hex)
      tlv += date_tlv
      
      time_tlv = Util.compose_tlv("ce", Time.now.strftime("%H%M").to_ubcd_hex)
      tlv += time_tlv
      
      # TODO: Clarify if SHA1 hash can be of arbitrary data, or of date + time. Arbirary hash seems to be accepted by the TIM
      hash_tlv = Util.compose_tlv("d4", Digest::SHA1.hexdigest(hash))
      tlv += hash_tlv
      
      cmd = Util.compose_command("80", "42", "01", "00", tlv, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("report signed result: #{ result }")
      return result
    end
    
    def report_span(from, to)
      tlv = ""
      
      date_tlv = Util.compose_tlv("cd", Time.now.strftime("%Y%m%d").to_ubcd_hex)
      tlv += date_tlv
      
      time_tlv = Util.compose_tlv("ce", Time.now.strftime("%H%M").to_ubcd_hex)
      tlv += time_tlv
      
      from_tlv = Util.compose_tlv("d0", from.to_ubcd_hex)
      tlv += from_tlv
      
      to_tlv = Util.compose_tlv("d1", to.to_ubcd_hex)
      tlv += to_tlv
      
      cmd = Util.compose_command("80", "42", "03", "00", tlv, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      result = parse_tlv(resp[0..-3])
      Insika.log("report span result: #{ result }")
      return result
    end
    
    def activate(pin)
      data = ""
      
      # 1st: Date
      date_tlv = Util.compose_tlv("cd", Time.now.strftime("%Y%m%d"))
      data += date_tlv
      
      # 2nd: Time
      time_tlv = Util.compose_tlv("ce", Time.now.strftime("%H%M"))
      data += time_tlv
      
      # 2nd: Time
      pin_tlv = Util.compose_tlv("c3", pin.to_hex_s)
      data += pin_tlv

      cmd = Util.compose_command("80", "42", "04", "00", data, "00")
      resp = transmit(cmd)
      stat = parse_status(resp[-2..-1])
      
      result = parse_tlv(resp[0..-3])
      Insika.log("TIM status extended result: #{ result }")
      
      return resp[0..-3].to_hex_s
    end
    
    def myparsetlv(data)
      parse_tlv(data)
    end
    
    def deactivate
      puts "Not yet supported"
    end
    

    
    private
    
    def transmit(cmd)
      Insika.log("Sending: #{ cmd.to_hex_s }")
      ret = @card.transmit(cmd)
      Insika.log("Result: #{ ret.to_hex_s }")
      return ret
    end
    
    def parse_tlv(tlv)
      tlv = tlv.to_hex_s.gsub(/\s+/, "")
      total_length = tlv.length
      result = {}
      done = nil
      pos = 0
      while pos < total_length
        #puts "TLV POS #{ pos }"
        idx_tag_start = pos
        idx_tag_end = pos + 1
        tag = tlv[idx_tag_start..idx_tag_end]
        
        idx_len_start = pos + 2
        idx_len_end = pos + 3
        len = tlv[idx_len_start..idx_len_end].to_i_from_hex
        
        idx_val_start = pos + 4
        idx_val_end = pos + 3 + 2 * len
        val = tlv[idx_val_start..idx_val_end]
        
        pos = idx_val_end + 1
        
        val_plain = nil
        tag_plain = nil
        case tag
          
        when "9e"
          tag_plain = "SIGNATURE" # [1] 2.6.1
          val_plain = Base32.encode(val.to_byte_s).gsub(/(....)/) { |m| "#{ m }-" }
          
        when "c0"
          tag_plain = "TIM_LIFECYCLE" # [1] 2.6.2
          case val
          when "00" then val_plain = "UNDEFINED"
          when "01" then val_plain = "INITIALIZED"
          when "02" then val_plain = "PERSONALIZED"
          when "03" then val_plain = "ACTIVATED"
          when "04" then val_plain = "DEACTIVATED"
          else val_plain = "UNKNOWN_VAL_#{ val }_FOR_TAG_#{ tag }"
          end
          
        when "c1"
          tag_plain = "TIM_SERIAL_NUMBER" # [1] 2.6.3
          val_plain = val.to_i_from_hex
          
        when "c2"
          tag_plain = "TIM_VERSION" # [1] 2.6.4
          val_plain = val.to_byte_s
          
        when "c4"
          tag_plain = "TAX_PAYER_ID" # [1] 2.6.6
          val_plain = val.to_byte_s
          
        when "c5"
          tag_plain = "TIM_CONSECUTIVE_NUMBER" # [1] 2.6.7
          val_plain = val.to_i_from_hex
          
        when "c8"
          tag_plain = "CURRENCY_CODE" # [1] 2.6.11
          val_plain = val.to_i_from_hex
          
        when "cd"
          tag_plain = "DATE_LAST_TRANSACTION_MONTH" # [1] 2.6.14
          if len == 3
            val_plain = val[0..3] + "-" + val[4..5]
          else
            val_plain = val[0..3] + "-" + val[4..5] + "-" + val[6..7]
          end
          
        when "cb"
          tag_plain = "SEQUENCE_TRANSACTIONS" # [1] 2.6.13
          val_plain = val.to_i_from_hex
          
        when "cc"
          tag_plain = "SEQUENCE_REPORTS" # [1] 2.6.13
          val_plain = val.to_i_from_hex
          
        when "cf"
          tag_plain = "MONTHS_WITH_TURNOVER" # [1] 2.3.2
          val_plain = val.to_i_from_hex
          
        when "d2"
          tag_plain = "SEQ_NO_TRANSACTION_FIRST" # [1] 2.6.13
          val_plain = val.to_i_from_hex
          
        when "d3"
          tag_plain = "SEQ_NO_TRANSACTION_LAST" # [1] 2.6.13
          val_plain = val.to_i_from_hex
          
        when "d8"
          tag_plain = :turnover
          val_plain = val.sbcd_hex_to_i / 100.0
          
        when "d9"
          tag_plain = :turnover_negative
          val_plain = val.sbcd_hex_to_i / 100.0
          
        when "da"
          tag_plain = :turnover_vat
          val_plain = val.sbcd_hex_to_i / 100.0
          
        when "db"
          tag_plain = :turnover_vat_rate
          val_plain = val.ubcd_hex_to_i / 100.0
          
        when /e[1-9]/
          tag_plain = "container#{ tag[1] }".to_sym
          val_plain = parse_tlv(val.to_byte_s)
          
        else
          tag_plain = tag
          val_plain = val
        end
        result[tag_plain] = val_plain
        
      end
      return result
    end
    
    # http://www.cardwerk.com/smartcards/smartcard_standard_ISO7816-4_5_basic_organizations.aspx
    def parse_status(status)
      status = status.to_hex_s
      
      sw1 = status[-4..-3]
      sw2 = status[-2..-1]
      
      case sw1
      when "67"
        case sw2
        when "00" then err = "LC_INVALID"
        else
          raise "Unknown sw2 #{ sw2.inspect } for sw1 #{ sw1.inspect }"
        end
        
      when "6a"
        case sw2
        when "82" then err = "FILE_NOT_FOUND"
        when "86" then err = "INVALID_P1_P2"
        else
          raise "Unknown sw2 #{ sw2.inspect } for sw1 #{ sw1.inspect }"
        end
          
      when "90"
        case sw2
        when "00"
          err = "NO_ERROR"
        else
          raise "Unknown sw2 #{ sw2.inspect } for sw1 #{ sw1.inspect }"
        end
          
      when "98"
        case sw2
        when "01" then err = "TIM_ERROR_TLV"
        when "02" then err = "TIM_ERROR_VALUE"
        when "03" then err = "TIM_ERROR_DATA_MISSING"
        when "04" then err = "TIM_ERROR_INVALID_CHARACTER"
        when "11" then err = "TIM_ERROR_DATE_FORMAT"
        when "12" then err = "TIM_ERROR_DATE_OUT_OF_RANGE"
        when "13" then err = "TIM_ERROR_CURRENCY"
        when "21" then err = "TIM_ERROR_TAX_VERIFICATION_FAILED"
        when "22" then err = "TIM_ERROR_NEGATIVE_TURNOVER"
        when "31" then err = "TIM_ERROR_INVALID_SIGNATURE"
        when "41" then err = "TIM_ERROR_INVALID_LIFECYCLE"
        when "e1" then err = "TIM_ERROR_MEMORY_FAILURE"
        when "e2" then err = "TIM_ERROR_DATA_CORRUPTED"
        when "ff" then err = "TIM_ERROR_NOT_SUPPORTED"
        else
          raise "Unknown sw2 #{ sw2.inspect } for sw1 #{ sw1.inspect }"
        end
        
      else
        raise "Unknown sw1 #{ sw1.inspect }"
      end
      
      Insika.log("Parsed status #{ err }")
      return err
    end
  end
end

class Integer
  include Insika::HexInteger
end

class String
  include Insika::HexString
end