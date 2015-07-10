module Insika
  
  def self.log(text)
    if defined?(ActiveRecord)
      ActiveRecord::Base.logger.info "[INSIKA] #{ text }"
    else
      puts "[INSIKA] #{ text }"
    end
  end
  
end