#pragma once

#include "../status.hpp"

class StatusIncreaseAgi : public Status<StatusIncreaseAgi> {
public:
	int cure_statuses();
};
