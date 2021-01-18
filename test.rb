#!/usr/bin/env ruby

require_relative './nmea2k'

class Tests
	class ExpectationError < StandardError; end

	def run
		passed = 0
		failed = 0
		self.methods.select { |m| m.to_s.start_with?('test_') }.each do |method|
			begin
				self.class.new.send(method)
				passed += 1
			rescue ExpectationError => e
				puts("FAILED: #{method}")
				puts(e)
				puts(e.backtrace)
				failed += 1
			end
		end
		puts("#{passed} tests passed, #{failed} tests failed")
	end

	def expect(bool)
		raise ExpectationError.new("expected truthy but got #{bool}") unless bool
	end

	def expect_eq(a, b)
		raise ExpectationError.new("expected #{a} == #{b}") unless a == b
	end

	def pgn_database
		@pgn_database ||= load_pgn_database
	end

	def test_pgn_serialization
		iso_request = ISORequestPGN.new(pgn_database, :pgn => 60928)
		expect_eq(iso_request.serialize, {:pgn=>59904, :payload=>"\x00\xEE\x00".b})
		iso_request.pgn = 126996
		expect_eq(iso_request.serialize, {:pgn=>59904, :payload=>"\x14\xF0\x01".b})
		iso_request.pgn = 59392
		expect_eq(iso_request.serialize, {:pgn=>59904, :payload=>"\x00\xE8\x00".b})
	end
end

Tests.new.run
