#!/usr/bin/env ruby

#----------------------------------------------------------------------------
# by Chuck Batson
# This code is given to the public domain by the author.
# Please just keep this credit and comment banner in the source code. :)
#
# Kindly consider contributing improvements to the community via
# pull request at https://github.com/cbatson/nmea2k
#
# WARNING: This code is very preliminary and a work in progress. There are
# known deficiencies, large portions of the code have not been tested, and
# it is likely to perform incorrectly or even fail in some circumstances.
# The author makes no warranty and accepts no liability. Your use of this
# code constitutes your agreement to the foregoing. You are responsible for
# your own testing and validation.
#
# Designed for Ruby 2.6.3
#----------------------------------------------------------------------------

require 'json'
require 'optparse'
require 'set'

class Driver
	BROADCAST_DESTINATION = 255

	attr_reader :path

	def initialize(pgn_database, options = {})
		@pgn_database = pgn_database
		if options[:device]
			@path = options[:device]
			@is_device = true
		elsif options[:file]
			@path = options[:file]
			@is_device = false
		else
			raise ArgumentError
		end
		@stats = Hash.new(0)
	end

	def device?
		@is_device
	end

	def allow_tx?
		device? && @allow_tx
	end

	def start
		reset_fast_packet(nil)
	end

	def stop
	end

	def update
		packet = read_packet
		ingest_packet(packet) if packet
	end

	def packets_coalesced?
		false
	end

	def stats
		@stats.dup
	end

	def self.driver_list
		ObjectSpace.each_object(Class).select { |klass| klass < Driver && klass.name.end_with?('Driver') }
	end

	def self.driver_name
		name.end_with?('Driver') ? name[0..-7] : nil
	end

	def self.class_from_name(driver_name)
		driver_names = driver_list.map(&:driver_name)
		return nil unless driver_names.include?(driver_name)
		klass_name = driver_name + 'Driver'
		Object.const_get(klass_name) rescue nil
	end

	protected

	def read_packet
	end

	def ingest_packet(packet)
		stat_inc(:frames)
		# From https://github.com/canboat/canboat/blob/master/common/common.h
 		# NMEA 2000 uses the 8 'data' bytes as follows:
 		# data[0] is an 'order' that increments, or not (depending a bit on implementation).
 		# If the size of the packet <= 7 then the data follows in data[1..7]
 		# If the size of the packet > 7 then the next byte data[1] is the size of the payload
 		# and data[0] is divided into 5 bits index into the fast packet, and 3 bits 'order
 		# that increases.
 		# This means that for 'fast packets' the first bucket (sub-packet) contains 6 payload
 		# bytes and 7 for remaining. Since the max index is 31, the maximal payload is
 		# 6 + 31 * 7 = 223 bytes
 		pgn = packet[:pgn]
		pgn_info = @pgn_database[pgn]
		if pgn_info
			pgn_type = pgn_info[:Type]
			if packets_coalesced? || pgn_type == :Single
				stat_inc(:packets)
				return packet
			elsif pgn_type == :Fast
				index = packet[:payload][0].ord & 0x1f
				if index == 0
					reset_fast_packet(packet)
				elsif expected_fast_packet(packet, index)
					@fast_packet[:payload] += packet[:payload][1..]
					if @fast_packet[:payload].size >= @fast_packet_size
						packet = @fast_packet
						packet[:payload] = packet[:payload][0...@fast_packet_size]
						reset_fast_packet(nil)
						stat_inc(:fast_packets)
						stat_inc(:packets)
						return packet
					end
				else
					stat_inc(:malformed_fast_packet)
					reset_fast_packet(nil)
				end
			else
				stat_inc(:unknown_pgn_type)
				stat_inc(:packets)
				return packet
			end
		else
			stat_inc(:unknown_pgn)
		end
		nil
	end

	def stat_inc(metric)
		@stats[metric] += 1
	end

	def reset_fast_packet(packet)
		@fast_packet = packet
		@fast_packet_index = 0
		if packet
			@fast_packet_size = packet[:payload][1].ord
			packet[:payload] = packet[:payload][2..]
		end
	end

	def expected_fast_packet(packet, index)
		@fast_packet_index += 1
		@fast_packet && (@fast_packet[:pgn] == packet[:pgn]) && (@fast_packet_index == index)
	end

	def parseMessageId(msgId)
		pgn = (msgId >> 8) & 0x1ffff
		if ((pgn & 0x0ff00) < 0x0f000)
			destination = pgn & 0xff
			pgn &= 0x1ff00
		else
			destination = 0xff
		end
		{
			:pgn => pgn,
			:source => msgId & 0xff,
			:destination => destination,
			:priority => (msgId >> 26) & 7,
		}
	end
end

class YDNUDriverBase < Driver
	def initialize(pgn_database, options = {})
		super
		put("YDNU SILENT #{allow_tx? ? 'OFF' : 'ON'}") if device?
	end

	def start
		super
		@file = File.open(path, allow_tx? ? 'r+' : 'r')
	end

	def stop
		@file.close
		@file = nil
	end

	protected

	CRLF = "\r\n".freeze

	def put(msg)
		@file.write(msg + CRLF) if allow_tx?
	end
end

class YDNU_RawDriver < YDNUDriverBase
	def start
		super
		put('YDNU MODE RAW') if device?
	end

	def read_packet
		# 04:04:45.667 R 0DF50B69 00 E8 00 00 00 00 00 FF
		line = @file.gets&.chomp
		raise EOFError if line.nil?
		time_h =  Integer(line[0...2], 10)
		time_m =  Integer(line[3...5], 10)
		time_s =  Integer(line[6...8], 10)
		time_msec = Integer(line[9...12], 10)
		timestamp = ((time_h * 60) + time_m) * 60 + time_s + time_msec * 0.001
		msgId = Integer(line[15...23], 16)
		parseMessageId(msgId).merge({
			:timestamp => timestamp,	# seconds since midnight
			:direction => line[13...14],
			:payload => [line[24..].delete(' ')].pack('H*')
		})
	end

	def packets_coalesced?
		false
	end
end

class YDNU_N2KDriver < YDNUDriverBase
	def start
		super
		put('YDNU MODE N2K') if device?
	end

	def read_packet
		while true
			packet = ingest_byte
			return packet if packet
		end
	end

	def packets_coalesced?
		true
	end

	protected

	def ingest_byte
		byte = @file.read(1)&.ord
		raise EOFError unless byte
		while true
			case @state.to_i
				when STATE_AWAIT_FIRST_START_DLE
					@state = STATE_AWAIT_FIRST_STX if byte == CHAR_DLE
				when STATE_AWAIT_FIRST_STX
					if byte == CHAR_STX
						@state = STATE_AWAIT_PACKET_ID
					else
						@state = STATE_AWAIT_FIRST_START_DLE
						next	# might be a DLE
					end
				when STATE_AWAIT_START_DLE
					if byte == CHAR_DLE
						@state = STATE_AWAIT_STX
					else
						stat_inc(:sync_start_dle)
					end
				when STATE_AWAIT_STX
					if byte == CHAR_STX
						@state = STATE_AWAIT_PACKET_ID
					else
						stat_inc(:sync_await_stx)
						@state = STATE_AWAIT_START_DLE
						next	# might be a DLE
					end
				when STATE_AWAIT_PACKET_ID
					@packet_id = byte
					@state = STATE_READ_SIZE
				when STATE_READ_SIZE
					@packet_size = byte
					@packet_data = EMPTY_DATA.dup
					@state = byte == CHAR_DLE ? STATE_READ_SIZE_DLE : STATE_READ_PAYLOAD
				when STATE_READ_SIZE_DLE
					if byte == CHAR_DLE
						@state = STATE_READ_PAYLOAD
					else
						stat_inc(:sync_size_dle)
						@state = STATE_AWAIT_STX	# previous character was already a DLE
						next
					end
				when STATE_READ_PAYLOAD
					if @packet_data.size >= @packet_size
						@state = STATE_READ_CHECKSUM
						next
					end
					@packet_data += byte.chr
					@state = STATE_READ_PAYLOAD_DLE if byte == CHAR_DLE
				when STATE_READ_PAYLOAD_DLE
					if byte == CHAR_DLE
						@state = STATE_READ_PAYLOAD
					else
						stat_inc(:sync_payload_dle)
						@state = STATE_AWAIT_STX	# previous character was already a DLE
						next
					end
				when STATE_READ_CHECKSUM
					@packet_checksum = byte
					@state = byte == CHAR_DLE ? STATE_READ_CHECKSUM_DLE : STATE_AWAIT_END_DLE
				when STATE_READ_CHECKSUM_DLE
					if byte == CHAR_DLE
						@state = STATE_AWAIT_END_DLE
					else
						stat_inc(:sync_checksum_dle)
						@state = STATE_AWAIT_STX	# previous character was already a DLE
						next
					end
				when STATE_AWAIT_END_DLE
					if byte == CHAR_DLE
						@state = STATE_AWAIT_ETX
					else
						stat_inc(:sync_end_dle)
						@state = STATE_AWAIT_START_DLE
					end
				when STATE_AWAIT_ETX
					@state = STATE_AWAIT_START_DLE
					if byte == CHAR_ETX
						return process_packet
					else
						stat_inc(:sync_await_etx)
						next	# might be a DLE
					end
			end
			break
		end
		nil
	end

	def process_packet
		unless validate_checksum
			stat_inc(:checksum_mismatch)
			return nil
		end
		unless @packet_data.size >= 11
			stat_inc(:packet_too_small)
			return nil
		end
		direction = case @packet_id
			when PACKETID_N2K_DATA
				'R'
			when PACKETID_N2K_REQ
				'T'
			else
				stat_inc(:unknown_packet_id)
				return nil
		end
		unless @packet_data.size == @packet_data[10].ord + 11
			stat_inc(:packet_incorrect_size)
			return nil
		end
		timestamp = @packet_data[6..9].unpack('L<').first * 0.001
		pgn = (@packet_data[3].ord << 16) | (@packet_data[2].ord << 8) | @packet_data[1].ord
		{
			:pgn => pgn,
			:source => @packet_data[5].ord,
			:destination => @packet_data[4].ord,
			:priority => @packet_data[0].ord & 7,
			:timestamp => timestamp,	# seconds since midnight
			:direction => direction,
			:payload => @packet_data[11..],
		}
	end

	def validate_checksum
		checksum = @packet_id + @packet_size + @packet_data.chars.map(&:ord).sum
		@packet_checksum == (-checksum) & 255
	end

	STATE_AWAIT_FIRST_START_DLE = 0
	STATE_AWAIT_FIRST_STX = 1
	STATE_AWAIT_START_DLE = 2
	STATE_AWAIT_STX = 3
	STATE_AWAIT_PACKET_ID = 4
	STATE_READ_SIZE = 5
	STATE_READ_SIZE_DLE = 6
	STATE_READ_PAYLOAD = 7
	STATE_READ_PAYLOAD_DLE = 8
	STATE_READ_CHECKSUM = 9
	STATE_READ_CHECKSUM_DLE = 10
	STATE_AWAIT_END_DLE = 11
	STATE_AWAIT_ETX = 12

	CHAR_DLE = 16
	CHAR_STX = 2
	CHAR_ETX = 3

	# See "Garmin Device Interface Specification" (001-00063-00) for additional values.
	# Also http://openskipper.org/openskipperwordpress/?cpage=1
	PACKETID_N2K_DATA = 147
	PACKETID_N2K_REQ = 148
	PACKETID_NGT_BEMCMD = 160	# Sometimes emitted by YDNU, but seems an Actisense thing

	EMPTY_DATA = ''.force_encoding(Encoding::ASCII_8BIT).freeze
end

#----------------------------------------------------------------------------

class Object
	alias :deep_freeze :freeze
end

class Array
	def deep_freeze
		each(&:deep_freeze)
	end
end

class Hash
	def deep_freeze
		each { |k, v| k.deep_freeze ; v.deep_freeze }
	end
end

#----------------------------------------------------------------------------

class PGNDatabase
	def initialize
		@pgns = {}
	end

	def load(file_path)
		db = File.open(file_path) do |file|
			JSON.load(file, nil, :symbolize_names => true, :create_additions => false)
		end
		pgn_list = db.delete(:PGNs)
		@pgns = Hash[pgn_list.map { |pgn| [pgn[:PGN], fixup_pgn(pgn)] }].deep_freeze
		@db = db.deep_freeze
	end

	def [](index)
		@pgns[index]
	end

	def key?(index)
		@pgns.key?(index)
	end

	protected

	def fixup_pgn(pgn)
		pgn[:Type] = pgn[:Type].to_sym
		pgn
	end
end

#----------------------------------------------------------------------------

class PacketInterpreter
	def initialize(pgn_database)
		@pgn_database = pgn_database
		@enum_cache = {}
	end

	def interpret(packet)
		pgn_desc = @pgn_database[packet[:pgn]]
		return packet unless pgn_desc
		{
			:pgn => packet[:pgn],
			:source => packet[:source],
			:destination => packet[:destination],
			:id => pgn_desc[:Id],
			:description => pgn_desc[:Description],
			:fields => fields(pgn_desc, packet),
		}
	end

	protected

	def fields(pgn_desc, packet)
		# TODO: Handle repeating fields
		result = Hash[pgn_desc[:Fields].map { |*args| interpret_field(pgn_desc, args[0], packet) }]
		if result['date'] && result['time']
			timestamp = result['date'][:value] * 24 * 60 * 60 + result['time'][:value]
			result.merge!('datetime' => { :value => timestamp, :display_value => Time.at(timestamp).utc })
		end
		result
	end

	def interpret_field(pgn_desc, field_desc, packet)
		field_desc = field_desc.last if field_desc.respond_to?(:last)
		field_value = {
			:description => field_desc[:Name] || field_desc[:Id],
		}
		field_value.merge!(case field_desc[:Type]
			when FIELDTYPE_ASCII_TEXT
				ascii_field_value(field_desc, packet)
			when FIELDTYPE_ASCII_OR_UNICODE
				unicode_field_value(field_desc, packet)
			when FIELDTYPE_INTEGER
				numeric_field_value(field_desc, packet, 1)
			when FIELDTYPE_DATE, FIELDTYPE_TIME
				numeric_field_value(field_desc, packet)
			when FIELDTYPE_LATITUDE
				latlon_field_value(field_desc, packet, 2, 'N', 'S')
			when FIELDTYPE_LONGITUDE
				latlon_field_value(field_desc, packet, 3, 'E', 'W')
			when FIELDTYPE_PRESSURE, FIELDTYPE_PRESSURE_HIRES
				numeric_field_value(field_desc, packet)
			when FIELDTYPE_TEMPERATURE, FIELDTYPE_TEMPERATURE_HIRES
				numeric_field_value(field_desc, packet)
			when nil	# numeric
				numeric_field_value(field_desc, packet)
			when FIELDTYPE_BINARY
				binary_field_value(field_desc, packet)
			when FIELDTYPE_LOOKUP_TABLE
				enum_field_value(pgn_desc, field_desc, packet)
			when FIELDTYPE_MANUFACTURER_CODE
				manufacturer_field_value(field_desc, packet)
			else
				{ :value => nil, :note => "unknown field type '#{field_desc[:Type]}'" }
		end)
		field_value.merge!(:units => field_desc[:Units]) if field_desc[:Units]
		[field_desc[:Id], field_value]
	end

	def latlon_field_value(field_desc, packet, degrees_digits, pos_suffix, neg_suffix)
		# Arithmetic in integer space to avoid potential issues with fractional minutes display
		value = extract_integer(field_desc, packet)
		suffix = value >= 0 ? pos_suffix : neg_suffix
		value = value.abs
		resolution = (1.0 / field_desc[:Resolution].to_f).to_i
		degrees_whole = (value / resolution).to_i
		value -= degrees_whole * resolution		# to fractional degrees
		value *= 60								# to minutes
		minutes_whole = (value / resolution).to_i
		value -= minutes_whole * resolution		# to fractional minutes
		minutes_frac = (value + resolution).to_i.to_s[1..5]
		display_value = sprintf("%0#{degrees_digits}d°%02d.%s'%s", degrees_whole, minutes_whole, minutes_frac, suffix)
		{ :value => extract_numeric(field_desc, packet), :display_value => display_value}
	end

	def unicode_field_value(field_desc, packet)
		# According to canboat:
		# STRINGLAU format is <len> <control> [ <data> ... ]
		# where <control> == 0 = UNICODE, but we don't know whether it is UTF16, UTF8, etc. Not seen in the wild yet!
		#       <control> == 1 = ASCII(?) or maybe UTF8?
		binary = extract_bytes(field_desc, packet)
		length = binary[0].ord - 2
		control = binary[1].ord
		{ :value => binary[2...length+2].force_encoding(Encoding::UTF_8).strip }
	end

	def ascii_field_value(field_desc, packet)
		bytes = extract_bytes(field_desc, packet)
		while bytes.size > 0 && bytes[-1].ord == 255
			bytes = bytes[0...-1]
		end
		bytes = bytes.split(0.chr).first || ''
		{ :value => bytes.force_encoding(Encoding::UTF_8).strip }
	end

	def manufacturer_field_value(field_desc, packet)
		manufacturer_code = extract_bits(field_desc, packet)
		{ :value => manufacturer_code, :display_value => MANUFACTURERS[manufacturer_code] || "MANUFACTURER-#{manufacturer_code}" }
	end

	def enum_field_value(pgn_desc, field_desc, packet)
		binary_value = extract_bits(field_desc, packet)
		display_value = enum_value(pgn_desc, field_desc, binary_value) || binary_value.to_s
		{ :value => binary_value, :display_value => display_value }
	end

	def enum_value(pgn_desc, field_desc, binary_value)
		cache_key = "#{pgn_desc[:Id]}|#{field_desc[:Id]}"
		enum_hash = @enum_cache[cache_key]
		unless enum_hash
			enum_hash = if field_desc[:EnumValues]
				Hash[field_desc[:EnumValues].map { |ev| [ev[:value].to_s, ev[:name]] }].deep_freeze
			else
				EMPTY_HASH
			end
			@enum_cache[cache_key] = enum_hash
		end
		enum_hash[binary_value.to_s]
	end

	def binary_field_value(field_desc, packet)
		{ :value => extract_bytes(field_desc, packet) }
	end

	def numeric_field_value(field_desc, packet, resolution = nil)
		{ :value => extract_numeric(field_desc, packet, resolution) }
	end

	def extract_bytes(field_desc, packet)
		start_bit = field_desc[:BitOffset]
		bit_length = field_desc[:BitLength]
		start_byte = start_bit >> 3
		end_byte = (start_bit + bit_length - 1) >> 3
		packet[:payload][start_byte..end_byte]
	end

	def extract_numeric(field_desc, packet, resolution = nil)
		resolution = (resolution || field_desc[:Resolution]).to_f
		value = extract_integer(field_desc, packet)
		if resolution != 0 && resolution != 1
			value *= resolution
		end
		value
	end

	def extract_integer(field_desc, packet)
		value = extract_bits(field_desc, packet)
		bit_length = field_desc[:BitLength]
		if field_desc[:Signed] && (value >> (bit_length - 1)) & 1 != 0
			value ^= (1 << bit_length) - 1
			value = -value - 1
		end
		value
	end

	def extract_bits(field_desc, packet)
		start_bit = field_desc[:BitOffset]
		bit_length = field_desc[:BitLength]
		start_byte = start_bit >> 3
		end_byte = (start_bit + bit_length - 1) >> 3
		accumulator = 0
		(start_byte..end_byte).reverse_each { |i| accumulator = (accumulator << 8) | (packet[:payload][i]&.ord || 255) }
		accumulator >>= start_bit & 7
		accumulator & ((1 << bit_length) - 1)
	end

	FIELDTYPE_ASCII_TEXT = 'ASCII text'.freeze
	FIELDTYPE_ASCII_OR_UNICODE = 'ASCII or UNICODE string starting with length and control byte'.freeze
	FIELDTYPE_BINARY = 'Binary data'.freeze
	FIELDTYPE_DATE = 'Date'.freeze
	FIELDTYPE_INTEGER = 'Integer'.freeze
	FIELDTYPE_LATITUDE = 'Latitude'.freeze
	FIELDTYPE_LONGITUDE = 'Longitude'.freeze
	FIELDTYPE_LOOKUP_TABLE = 'Lookup table'.freeze
	FIELDTYPE_MANUFACTURER_CODE = 'Manufacturer code'.freeze
	FIELDTYPE_PRESSURE = 'Pressure'.freeze
	FIELDTYPE_PRESSURE_HIRES = 'Pressure (hires)'.freeze
	FIELDTYPE_TEMPERATURE = 'Temperature'.freeze
	FIELDTYPE_TEMPERATURE_HIRES = 'Temperature (hires)'.freeze
	FIELDTYPE_TIME = 'Time'.freeze

	MANUFACTURERS = {
		# From "NMEA 2000 Registration Numbers" April 9, 2014
		# https://www.nmea.org/Assets/20140409%20nmea%202000%20registration%20list.pdf
		174 => 'AB VOLVO/VOLVO PENTA',
		199 => 'ACTIA CORPORATION',
		273 => 'ACTISENSE',
		578 => 'ADVANSEA',
		215 => 'AETNA ENGINEERING/FIREBOY-XINTEX',
		135 => 'AIRMAR',
		459 => 'ALLTEK MARINE ELECTRONICS CORP',
		274 => 'AMPHENOL LTW TECHNOLOGY',
		502 => 'ATTWOOD MARINE',
		381 => 'B&G',
		185 => 'BEEDE ELECTRICAL',
		295 => 'BEP',
		396 => 'BEYOND MEASURE',
		148 => 'BLUE WATER DATA',
		163 => 'EVINRUDE/BRP BOMBARDIER',
		394 => 'CAPI 2',
		176 => 'CARLING TECHNOLOGIES',
		165 => 'CPAC SYSTEMS AB',
		286 => 'COELMO SRL ITALY',
		404 => 'COM NAV',
		440 => 'CUMMINS',
		329 => 'DIEF',
		437 => 'DIGITAL YACHT LIMITE',
		201 => 'DISENOS Y TECHNOLOGIA',
		211 => 'DNA GROUP, INC.',
		426 => 'EGERSUND MARINE ELECTRONICS AS',
		373 => 'ELECTRONIC DESIGN',
		427 => 'EM-TRAK MARINE ELECTRONICS LTD',
		224 => 'EMMI NETWORK',
		304 => 'EMPIR BUS',
		243 => 'ERIDE',
		1863 => 'FARIA INSTRUMENTS',
		356 => 'FISCHER PANDA',
		192 => 'FLOSCAN INSTRUMENT CO., INC.',
		1855 => 'FURUNO USA',
		419 => 'FUSION',
		78 => 'FW MURPHY',
		229 => 'GARMIN',
		385 => 'GEONA V',
		378 => 'GLENDINNING',
		475 => 'GME aka Standard Communications Pty LTD',
		272 => 'GROCO',
		283 => 'HAMILTON JET',
		88 => 'HEMISPHERE GPS',
		257 => 'HONDA MOTOR',
		467 => 'HUMMINGBIRD MARINE ELECTRONICS',
		315 => 'ICOM',
		1853 => 'JAPAN RADIO CO',
		1859 => 'KVASAR AB',
		579 => 'KVH',
		85 => 'KOHLER POWER SYSTEMS',
		345 => 'KOREA MARITIME UNIVERSITY',
		499 => 'LCJ CAPTEURS',
		1858 => 'LITTON',
		400 => 'LIVORSI MARINE',
		140 => 'LOWRANCE ELECTRONICS',
		137 => 'MARETRON',
		571 => 'MARINECRAFT (SOUTH KOREA)',
		307 => 'MBW TECHNOLOGIES (FORMELY MAS TECHNOLOGIES)',
		355 => 'MASTERVOLT',
		144 => 'MERCURY MARINE',
		1860 => 'MMP',
		198 => 'MYSTIC VALLEY COMMUNICATIONS',
		529 => 'NATIONAL INSTRUMENTS',
		147 => 'NAUTIBUS ELECTRONIC GMBH',
		275 => 'NAVICO',
		1852 => 'NAVIONICS',
		503 => 'NAVIOP',
		193 => 'NOBELTEC',
		517 => 'NOLAND ENGINEERING',
		374 => 'NORTHERN LIGHTS',
		1854 => 'NORTHSTAR TECHNOLOGIES',
		305 => 'NOVATEL',
		478 => 'OCEAN SAT BV',
		161 => 'OFFSHORE SYSTEMS UK',
		573 => 'OROLIA LTD (aka McMurdo)',
		328 => 'QWERTY',
		451 => 'PARKER HANNIFIN',
		1851 => 'RAYMARINE, INC.',
		370 => 'ROLLS ROYCE MARINE',
		384 => 'ROSE POINT NAVIGATION SYSTEMS',
		235 => 'SAILORMADE MARINE TELEMETRY/TETRA TECHNOLOGY LTD.',
		580 => 'SAN JOSE TECHNOLOGIES',
		460 => 'SAN GIORGIO S.E.I.N. srl',
		1862 => 'SANSHIN INDUSTRIES/YAMAHA MARINE',
		471 => 'SEA CROSS MARINE AB',
		285 => 'SEA RECOVERY',
		1857 => 'SIMRAD',
		470 => 'SITEX',
		306 => 'SLEIPNER MOTOR AS',
		1850 => 'TELEFLEX',
		351 => 'THRANE AND THRANE',
		431 => 'TOHATSU CO JP',
		518 => 'TRANSAS USA',
		1856 => 'TRIMBLE',
		422 => 'TRUE HEADING',
		80 => 'TWIN DISC',
		591 => 'UNITED STATES COAST GUARD',
		1861 => 'VECTOR CANTECH',
		466 => 'VEETHREE',
		421 => 'VERTEX STANDARD CO LTD',
		504 => 'VESPER MARINE',
		358 => 'VICTRON',
		493 => 'WATCHEYE',
		154 => 'WESTERBEKE CORP.',
		168 => 'XANTREX TECHNOLOGY',
		583 => 'YACHTCONTROL',
		233 => 'YACHT MONITORING SOLUTIONS',
		172 => 'YANMAR/YANMAR DIESEL',
		228 => 'ZF MARINE ELECTRONICS',
		# Manually added
		717 => 'YACHT DEVICES LTD.',
	}.deep_freeze

	EMPTY_HASH = {}.freeze
end

#----------------------------------------------------------------------------

class ByteBuffer
	def initialize(data: nil, length: nil)
		if !data.nil?
			@data = data.dup
		elsif !length.nil?
			@data = 255.chr * length
		else
			raise ArgumentError.new('must specify either data or length')
		end
	end

	def data
		@data.dup
	end

	def length
		@data.size
	end

	def read_bytes()
		# TODO
	end

	def read_bits
		# TODO
	end

	def write_bytes(bytes, bit_start, bit_length)
		if bit_start < 0 || bit_length < 1
			raise ArgumentError
		end
		if bit_start & 7 != 0
			raise NotImplementedError
		end
		if bit_length & 7 != 0
			raise NotImplementedError
		end
		byte_length = bit_length >> 3
		if bytes.size < byte_length
			raise ArgumentError
		end
		byte_start = bit_start >> 3
		bytes = bytes[0...byte_length]
		@data = @data[0...byte_start] + bytes + @data[byte_start + byte_length..-1]
		nil
	end

	def write_bits(value, bit_start, bit_length)
		if bit_start < 0 || bit_length < 1
			raise ArgumentError
		end
		if bit_length > 32
			raise NotImplementedError
		end
		if bit_start + bit_length > length * 8
			raise ArgumentError
		end
		byte_start = bit_start >> 3
		byte_end = (bit_start + bit_length - 1) >> 3
		accumulator = 0
		(byte_start..byte_end).reverse_each { |i| accumulator = (accumulator << 8) | @data[i].ord }
		bit_start &= 7
		mask = ((1 << bit_length) - 1) << bit_start
		accumulator = (accumulator & ~mask) | ((value << bit_start) & mask)
		(byte_start..byte_end).each { |i| @data[i] = (accumulator & 255).chr; accumulator >>= 8 }
	end
end

#----------------------------------------------------------------------------

class PGN
	attr_reader :priority

	def initialize(pgn_database, fields = {})
		raise ArgumentError.new("PGN ID #{pgn_id} not in database") unless pgn_database.key?(pgn_id)
		@_pgn_desc = pgn_database[pgn_id]
		@priority = 6
		@fields = {}
		fields.each do |key, value|
			_set_field(key, value)
		end
	end

	def pgn_id
		self.class::PGN_ID
	end

	# returns a packet
	def serialize
		buffer = ByteBuffer.new(length: _pgn_desc[:Length])
		_pgn_desc[:Fields].each { |*args| _serialize_field(args[0], buffer) }
		{
			:pgn => pgn_id,
			:payload => buffer.data,
		}
	end

	# TODO: move deserialization here and get rid of PGN interpreter
	def self.deserialize(pgn_database, pgn_interpreter, packet)
		pgn_id = packet[:pgn]
		pgn_class = class_for_id(pgn_id)
		return nil unless pgn_class		# should not be possible
		pgn_obj = pgn_class.new(pgn_database)
		pgn_obj._deserialize(pgn_interpreter, packet)
		pgn_obj
	end

	def respond_to?(meth_name, include_all = false)
		return true if super
		field_name, _ = _method_to_field(meth_name)
		_has_field?(field_name)
	end

	def method_missing(meth_name, *args)
		field_name, suffix = _method_to_field(meth_name)
		if _has_field?(field_name)
			case suffix
				when '='
					_set_field(field_name, args[0])
				else
					_get_field(field_name)
			end
		else
			super
		end
	end

	protected

	attr_reader :_pgn_desc

	# Override as needed
	def permitted_fields
		nil		# nil means all fields are permitted
	end

	# Override as needed
	def forbidden_fields
		nil		# nil means no fields are forbidden
	end

	def _serialize_field(field_desc, buffer)
		field_desc = field_desc.last if field_desc.respond_to?(:last)
		field_id = field_desc[:Id].to_sym
		return unless @fields.key?(field_id)
		field_type = field_desc[:Type]
		field_value = @fields[field_id]
		case field_type
			when FIELDTYPE_ASCII_TEXT
				_serialize_ascii_field(field_desc, field_value, buffer)
			#when FIELDTYPE_ASCII_OR_UNICODE
			#	unicode_field_value(field_desc, packet)
			when FIELDTYPE_INTEGER
				_serialize_numeric_field(field_desc, field_value, buffer, 1)
			#when FIELDTYPE_DATE, FIELDTYPE_TIME
			#	numeric_field_value(field_desc, packet)
			#when FIELDTYPE_LATITUDE
			#	latlon_field_value(field_desc, packet, 2, 'N', 'S')
			#when FIELDTYPE_LONGITUDE
			#	latlon_field_value(field_desc, packet, 3, 'E', 'W')
			#when FIELDTYPE_PRESSURE, FIELDTYPE_PRESSURE_HIRES
			#	numeric_field_value(field_desc, packet)
			#when FIELDTYPE_TEMPERATURE, FIELDTYPE_TEMPERATURE_HIRES
			#	numeric_field_value(field_desc, packet)
			when nil	# numeric
				_serialize_numeric_field(field_desc, field_value, buffer)
			#when FIELDTYPE_BINARY
			#	binary_field_value(field_desc, packet)
			#when FIELDTYPE_LOOKUP_TABLE
			#	enum_field_value(pgn_desc, field_desc, packet)
			#when FIELDTYPE_MANUFACTURER_CODE
			#	manufacturer_field_value(field_desc, packet)
			else
				raise NotImplementedError.new("unknown field type '#{field_type}'")
		end
	end

	def _serialize_ascii_field(field_desc, field_value, buffer)
		field_length = field_desc[:BitLength] >> 3
		field_value = (field_value + 0.chr)[0...field_length]
		buffer.write_bytes(field_value, field_desc[:BitOffset], field_desc[:BitLength])
	end

	def _serialize_numeric_field(field_desc, field_value, buffer, scale = nil)
		scale = (field_desc[:Resolution] || 1) if scale.nil?
		scale = scale.to_f
		field_value = (field_value / scale).to_i
		field_max = 1 << field_desc[:BitLength]
		if field_desc[:Signed]
			field_min = -(field_max >> 1)
			field_max = (field_max >> 1) - 1
		else
			field_min = 0
		end
		if field_value < field_min or field_value > field_max
			# TODO: move this checking into field assignment
			raise ArgumentError.new('value out of range for field')
		end
		buffer.write_bits(field_value, field_desc[:BitOffset], field_desc[:BitLength])
	end

	def _deserialize(packet_interpreter, packet)
		interp = packet_interpreter.interpret(packet)
		unless interp[:id] == self.class::PGN_ID
			raise ArgumentError
		end
		@fields = {}
		field_list.each do |field_name|
			field_value = interp[:fields][field_name.to_s]
			field_value = field_value[:value] unless field_value.nil?
			_set_field(field_name, field_value) unless field_value.nil?
		end
	end

	def _get_field(name)
		_has_field?(name) ? @fields[name] : _undefined(name)
	end

	def _set_field(name, value)
		_has_field?(name) ? @fields[name] = value : _undefined(name)
	end

	def _undefined(name)
		raise NoMethodError.new("undefined method `#{name}' for #{self}")
	end

	def _has_field?(name)
		_field_list.include?(name)
	end

	def _field_list
		@field_list ||= _construct_field_list
	end

	def _construct_field_list
		fields = _pgn_desc[:Fields]
		fields = fields.values if fields.is_a?(Hash)
		fields = fields.map { |f| f[:Id].to_sym }.uniq
		if permitted_fields
			fields &= permitted_fields
		end
		if forbidden_fields
			fields -= forbidden_fields
		end
		fields.to_set.freeze
	end

	def _method_to_field(meth_name)
		field_name = meth_name.to_s
		suffix = field_name.end_with?('=') ? '=' : nil
		field_name = field_name[0...-1] if suffix
		[field_name.to_sym, suffix]
	end

	class << self
		private

		def class_for_id(pgn_id)
			classes_by_id[pgn_id] ||= new_class_for_id(pgn_id)
		end

		def classes_by_id
			@classes_by_id ||= construct_classes_by_id
		end

		def construct_classes_by_id
			klasses = ObjectSpace.each_object(Class).select { |klass| klass < PGN }
			Hash[klasses.map { |klass| [klass::PGN_ID, klass] }]
		end

		def new_class_for_id(pgn_id)
			Class.new(self) { |k| k.const_set('PGN_ID', pgn_id) }
		end
	end

	FIELDTYPE_ASCII_TEXT = 'ASCII text'.freeze
	FIELDTYPE_ASCII_OR_UNICODE = 'ASCII or UNICODE string starting with length and control byte'.freeze
	FIELDTYPE_BINARY = 'Binary data'.freeze
	FIELDTYPE_DATE = 'Date'.freeze
	FIELDTYPE_INTEGER = 'Integer'.freeze
	FIELDTYPE_LATITUDE = 'Latitude'.freeze
	FIELDTYPE_LONGITUDE = 'Longitude'.freeze
	FIELDTYPE_LOOKUP_TABLE = 'Lookup table'.freeze
	FIELDTYPE_MANUFACTURER_CODE = 'Manufacturer code'.freeze
	FIELDTYPE_PRESSURE = 'Pressure'.freeze
	FIELDTYPE_PRESSURE_HIRES = 'Pressure (hires)'.freeze
	FIELDTYPE_TEMPERATURE = 'Temperature'.freeze
	FIELDTYPE_TEMPERATURE_HIRES = 'Temperature (hires)'.freeze
	FIELDTYPE_TIME = 'Time'.freeze
end

class ISORequestPGN < PGN
	PGN_ID = 59904
	# Attributes:
	# => pgn (Integer)
end

#----------------------------------------------------------------------------

PROG_NAME = File.basename(__FILE__)
DEFAULT_DRIVER_NAME = YDNU_N2KDriver.driver_name.freeze

def parse_params
	drivers = Driver.driver_list.map(&:driver_name) - [DEFAULT_DRIVER_NAME]
	drivers = [DEFAULT_DRIVER_NAME + ' (default)'] + drivers
	params = {}
	OptionParser.new do |opts|
		opts.banner = "Usage: #{PROG_NAME} [options]"
		opts.on('-d', '--device=PATH', 'device to read/write')
		opts.on('-f', '--file=PATH', 'file to read')
		opts.on('-h', '--help', 'show this help') do
			puts opts
			exit
		end
		opts.on('-r', '--driver=NAME', "driver: #{drivers.join(', ')}")
		opts.on('-s', '--stats', 'display stats on exit')
	end.parse!(into: params)
	params[:driver] ||= DEFAULT_DRIVER_NAME
	params
end

def error(msg)
	puts("#{PROG_NAME}: error: #{msg}")
	exit(1)
end

def load_pgn_database
	PGNDatabase.new.tap do |pgn_database|
		pgn_database.load('/Users/chuck/projects/canboat/analyzer/pgns.json')
	end
end

def main
	pgn_database = load_pgn_database

	params = parse_params

	if params[:file] && params[:device]
		error('please specify either a device or file, not both')
	end

	driver_class = Driver.class_from_name(params[:driver])
	unless driver_class
		error("unrecognized driver name: #{params[:driver]}")
	end
	driver = driver_class.new(pgn_database, params)
	driver.start

	packet_interpreter = PacketInterpreter.new(pgn_database)

	begin
		while true
			packet = driver.update
			puts(packet_interpreter.interpret(packet)) if packet
		end
	rescue EOFError
		# ok
	ensure
		puts(driver.stats) if params[:stats]
		driver.stop
	end
end

if __FILE__ == $0
	main
end
