#ifndef STATUS_STATUS_LIST_HPP
#define STATUS_STATUS_LIST_HPP

#include <variant>
#include <iostream>


#include "status.hpp"

#include "statuses/SCAssumptio.hpp"
#include "statuses/SCBlessing.hpp"
#include "statuses/SCDeluge.hpp"
#include "statuses/SCIncreaseAgi.hpp"


enum class StatusType {
	SC_NONE,
	SC_BLESSING,
	SC_INCREASEAGI,
	SC_DELUGE,
	SC_ASSUMPTIO,
};

using PolyStatus = std::variant<StatusBlessing, StatusIncreaseAgi, StatusDeluge, StatusAssumptio>;

#endif
