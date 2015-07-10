# [1] = INSIKA TIM Interface Documentation

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
              }
            ]
  }
  
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