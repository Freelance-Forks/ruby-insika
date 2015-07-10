# [1]: INSIKA TIM Interface Documentation T.1.1.0.-02

require "smartcard"

dir = File.dirname(__FILE__)
Dir[File.expand_path("#{dir}/insika/*.rb")].uniq.each do |file|
  require file
end

module Insika
  
  @@rid = "d2 76 00 01 48" # Registered Identifier, [1] p. 29 and http://www.kartenbezogene-identifier.de/de/rapi/rid-liste.html
  @@pix = "54 49 4d" # Proprietary application identifier extension, "TIM" [1] p. 29
  
  def self.rid
    @@rid
  end
  
  def self.rid=(rid)
    @@rid = rid
  end
  
  def self.pix
    @@pix
  end
  
  def self.pix=(pix)
    @@pix = pix
  end
  
  def self.setup
    yield self
  end
  
end