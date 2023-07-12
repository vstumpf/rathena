#pragma once

#include "../status.hpp"

class StatusDeluge : public Status<StatusDeluge> {
public:
	int cure_statuses();
};
