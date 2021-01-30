#!/usr/bin/env ruby

require_relative './nmea2k'

class Tests
	class ExpectationError < StandardError; end

	def run
		passed = 0
		failed = 0
		self.methods.select { |m| m.to_s.start_with?('test_') }.each do |method|
			begin
				self.class.new.run_single(method)
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

	def run_single(method)
		before
		send(method)
		after
	end

	def expect(bool)
		raise ExpectationError.new("expected truthy but got #{bool}") unless bool
	end

	def expect_eq(a, b)
		raise ExpectationError.new("expected #{a} == #{b}") unless a == b
	end

	def expect_neq(a, b)
		raise ExpectationError.new("expected #{a} != #{b}") unless a != b
	end

	def pgn_database
		@pgn_database ||= load_pgn_database
	end

	def before
		PGN.pgn_database = pgn_database
	end

	def after
	end

	def test_pgn_serialization
		iso_request = ISORequestPGN.new(:pgn => 60928)
		expect_eq(iso_request.serialize, {:pgn=>59904, :payload=>"\x00\xEE\x00".b})
		iso_request.f_pgn = 126996
		expect_eq(iso_request.serialize, {:pgn=>59904, :payload=>"\x14\xF0\x01".b})
		iso_request.f_pgn = 59392
		expect_eq(iso_request.serialize, {:pgn=>59904, :payload=>"\x00\xE8\x00".b})
	end

	def test_iso_address_claim_equality
		ac1 = ISOAddressClaimPGN.new
		ac1.f_uniqueNumber = 1234
		ac1.f_manufacturerCode = 717
		ac1.f_deviceInstanceLower = 12
		ac1.f_deviceInstanceUpper = 34
		ac1.f_deviceFunction = 1
		ac1.f_deviceClass = 2
		ac1.f_systemInstance = 3
		ac1.f_industryGroup = 4
		ac2 = ac1.dup
		expect_eq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_uniqueNumber += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_manufacturerCode += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_deviceInstanceLower += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_deviceInstanceUpper += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_deviceFunction += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_deviceClass += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_systemInstance += 1
		expect_neq(ac1, ac2)

		ac2 = ac1.dup
		ac2.f_industryGroup += 1
		expect_neq(ac1, ac2)
	end

	def test_pgn_equality
		pgn = ISORequestPGN.new
		expect_eq(pgn == nil, false)
		expect_eq(pgn != nil, true)
		expect_eq(pgn == pgn, true)
		expect_eq(pgn != pgn, false)
		pgn2 = ISOAcknowledgementPGN.new
		expect_eq(pgn == pgn2, false)
		expect_eq(pgn != pgn2, true)
		pgn2 = pgn.dup
		expect_eq(pgn == pgn2, true)
		expect_eq(pgn != pgn2, false)
	end
end

Tests.new.run
