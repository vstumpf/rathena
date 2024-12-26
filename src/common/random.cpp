// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "random.hpp"

std::uniform_int_distribution<int32> int31_distribution = std::uniform_int_distribution<int32>(0, SINT32_MAX);

/// Generates a random number in the interval [0, SINT32_MAX]
int32 rnd( void ){
	return int31_distribution( generator );
}

constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

std::string rnd_string(size_t length) {
	std::string str;
	str.reserve(length);
	for (size_t i = 0; i < length; ++i) {
		str.push_back(static_cast<char>(rnd_value<int>(0, alphabet.length() - 1)));
	}
	return str;
}
