require 'securerandom'

module PasswordGenerator
  # Extend String class with an entropy method that records the amount
  # of entropy used to get the String.
  class StringWithEntropy < ::String
    attr_reader :entropy
    def initialize(string = "", entropy = 0.0)
      @entropy = entropy
      super(string)
    end

    def +(other)
      super_result = super

      if super_result.respond_to?(:to_str)
        if other.respond_to?(:entropy)
          self.class.new(super_result, @entropy + other.entropy)
        else
          self.class.new(super_result, @entropy)
        end
      else
        super_result
      end
    end

    def <<(other)
      @entropy += other.entropy if other.respond_to?(:entropy)
      super
    end
  end

  class Runner
    def initialize(options)
      @options = options
    end

    def self.from_argv(argv)
      options = {
        bits: 40,
        with: :words,
      }

      OptionParser.new do |opts|
        opts.on("--bits=BITS") do |bits|
          options[:bits] = bits.to_i
        end

        opts.on("--with=WITH") do |with|
          raise "--with value must be one of: #{GeneratorTypes.keys.join(", ")}" if !GeneratorTypes.has_key?(with.to_sym)
          options[:with] = with.to_sym
        end
      end.parse(argv)

      new(options)
    end

    def run(output = $stdout)
      gen_info = GeneratorTypes[@options[:with]] || raise("invalid generator information")
      gen_parts = [gen_info[:generator], gen_info[:separator]].dup
      pw = StringWithEntropy.new

      # Now tack on more parts until we reach enough entropy.
      while pw.entropy < @options[:bits]
        gen_parts.push(next_gen = gen_parts.shift)
        pw << (next_gen.respond_to?(:generate) ? next_gen.generate : next_gen)
      end

      output.puts "Your Secure Password is: #{pw}"
      output.puts "Bits Entropy of Security: %.2f" % pw.entropy
      output.puts "Length of Password: #{pw.size} characters"
    end
  end

  # Generate a piece of a password, to produce input for Generator.
  # This class is abstract, and provides the randomness routines shared
  # by its subclasses.
  class SimpleGenerator
    protected
    def bits_entropy(number)
      Math.log(number) / Math.log(2)
    end

    def secure_rand(number)
      SecureRandom.random_number(number)
    end

    def rand_index(array)
      array[secure_rand(array.size)]
    end
  end

  # Picks something randomly from a set.  This is generally meant to be subclassed.
  class Picker < SimpleGenerator
    def generate
      StringWithEntropy.new(rand_index(selection_set), minimum_entropy)
    end

    def minimum_entropy
      bits_entropy(selection_set.size)
    end
  end

  # Selects a random word from a list.
  class WordListPicker < Picker
    def initialize(filename = nil)
      @wordlist_filename = filename || File.join(File.dirname(__FILE__), "wordlist.txt")
    end

    def words
      @words ||= File.read(@wordlist_filename).split(/\n/).uniq.reject { |word| word.empty? }
    end
    alias selection_set words
  end

  # Selects a random printable character, or maybe also space.
  class CharPicker < Picker
    def initialize(ranges = nil, exclusions = nil)
      @ranges = ranges ? [*ranges] : [(" ".."~")]
      @exclusions = exclusions
    end

    def characters
      @characters ||= begin
        chars = @ranges.inject([]) { |a, range| range = [range] if !range.respond_to?(:to_a) ; a.push(*range.to_a) }.uniq
        @exclusions.each { |excl| chars -= excl.to_a } if @exclusions
        chars
      end
    end
    alias selection_set characters

    def self.new_upper
      new(["A".."Z"])
    end

    def self.new_lower
      new(["a".."z"])
    end

    def self.new_number
      new(["0".."9"])
    end

    def self.new_number_with_shifts
      new(["0".."9", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")"])
    end

    def self.new_symbol
      new(["!".."~"], [("0".."9"), ("A".."Z"), ("a".."z")])
    end
  end

  class CasePicker < Picker
    def initialize(string)
      @string = string
    end

    def selection_set
      [@string.downcase, @string.upcase].uniq
    end
  end

  class NumberShiftPicker < Picker
    def initialize(string)
      @string = string
    end

    def selection_set
      [@string.downcase, @string.upcase].uniq
    end
  end

  # Appends strings from other generators together.
  class AppendGenerator < SimpleGenerator
    def initialize(generators, separator = "")
      @generators = generators
      @separator = separator
    end

    def generate
      @generators.inject(StringWithEntropy.new) do |str, gen|
        str << (@separator.respond_to?(:generate) ? @separator.generate : @separator) if !str.empty?
        str << gen.generate
      end
    end

    def minimum_entropy
      @generators.inject(0.0) { |e, gen| e + gen.entropy }
    end
  end

  class CapitalizeModifier < SimpleGenerator
    def initialize(generator, options = {})
      @generator = generator
      @method = options[:method] || :first_last
    end

    def generate
      str = @generator.generate

      if str != str.downcase
        str
      elsif str.size == 1
        CasePicker.new(str).generate
      else
        CasePicker.new(str[0]).generate << StringWithEntropy.new(str[1..-2], str.entropy) << CasePicker.new(str[-1]).generate
      end
    end

    def minimum_entropy
      @generator.minimum_entropy
    end
  end

  GeneratorTypes = {
    words: {
      generator: PasswordGenerator::WordListPicker.new,
      separator: " ",
    },
    words_numbers: {
      generator: PasswordGenerator::WordListPicker.new,
      separator: PasswordGenerator::CharPicker.new_number,
    },
    words_shiftnumbers: {
      generator: PasswordGenerator::WordListPicker.new,
      separator: PasswordGenerator::CharPicker.new_number_with_shifts,
    },
    ascii: {
      generator: PasswordGenerator::CharPicker.new,
      separator: "",
    },
    ascii_lower: {
      generator: PasswordGenerator::CharPicker.new(nil, [("A".."Z")]),
      separator: "",
    },
    lower_number: {
      generator: PasswordGenerator::CharPicker.new([("0".."9"), ("a".."z")]),
      separator: "",
    },
    words_cases: {
      generator: PasswordGenerator::CapitalizeModifier.new(PasswordGenerator::WordListPicker.new),
      separator: " ",
    },
    words_cases_numbers: {
      generator: PasswordGenerator::CapitalizeModifier.new(PasswordGenerator::WordListPicker.new),
      separator: PasswordGenerator::CharPicker.new_number,
    },
    words_cases_shiftnumbers: {
      generator: PasswordGenerator::CapitalizeModifier.new(PasswordGenerator::WordListPicker.new),
      separator: PasswordGenerator::CharPicker.new_number_with_shifts,
    },
  }

end
