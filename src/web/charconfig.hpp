// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#ifndef CHARCONFIG_CONTROLLER_HPP
#define CHARCONFIG_CONTROLLER_HPP

#include "controller.hpp"

class CharConfigController : Controller {

public:
	CharConfigController(const Request &req, Response &res) : Controller(req, res) {};
	void loadCharConfig();
	void saveCharConfig();

	static void save(const Request &req, Response &res);
};

#endif