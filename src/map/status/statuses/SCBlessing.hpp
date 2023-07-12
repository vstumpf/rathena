#pragma once

#include "../status.hpp"

class StatusBlessing : public Status<StatusBlessing> {
public:
	int cure_statuses(/*struct block_list& bl, status_change &sc*/);
};
