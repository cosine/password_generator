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
          raise "with must be words or ascii" if !%w[words words_numbers ascii ascii_lower lower_number].include?(with)
          options[:with] = with.to_sym
        end
      end.parse(argv)

      new(options)
    end

    def run(output = $stdout)
      if @options[:with] == :ascii
        base_gen = PasswordGenerator::CharPicker.new
        separator = ""
      elsif @options[:with] == :ascii_lower
        base_gen = PasswordGenerator::CharPicker.new(nil, [("A".."Z")])
        separator = ""
      elsif @options[:with] == :lower_number
        base_gen = PasswordGenerator::CharPicker.new([("0".."9"), ("a".."z")])
        separator = ""
      elsif @options[:with] == :words_numbers
        base_gen = PasswordGenerator::WordListPicker.new
        separator = PasswordGenerator::CharPicker.new_number
      else
        base_gen = PasswordGenerator::WordListPicker.new
        separator = " "
      end

      separator_entropy = (separator.respond_to?(:entropy) ? separator.entropy : 0)
      needed = (@options[:bits] / (base_gen.entropy.to_f + separator_entropy)).ceil
      gen = PasswordGenerator::AppendGenerator.new([base_gen] * needed, separator)
      pw = gen.generate
      pw << separator.generate if pw.entropy < @options[:bits]
      output.puts "Your Secure Password is: #{pw}"
      output.puts "Bits Entropy of Security: %.2f" % pw.entropy
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
      StringWithEntropy.new(rand_index(selection_set), entropy)
    end

    def entropy
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
        chars = @ranges.inject([]) { |a, range| a.push(*range.to_a) }.uniq
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

    def self.new_symbol
      new(["!".."~"], [("0".."9"), ("A".."Z"), ("a".."z")])
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

    def entropy
      @generators.inject(0.0) { |e, gen| e + gen.entropy }
    end
  end
end
