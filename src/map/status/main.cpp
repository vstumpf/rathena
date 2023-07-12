#include <iostream>
#include <unordered_map>
#include <variant>

#include "status.hpp"
#include "status_list.hpp"

class StatusChange {
public:
	std::unordered_map<StatusType, PolyStatus> status_map;
};

int main() {

	StatusChange sc;

	sc.status_map.emplace(StatusType::SC_BLESSING, StatusBlessing{});
	sc.status_map.emplace(StatusType::SC_INCREASEAGI, StatusIncreaseAgi{});
	sc.status_map.emplace(StatusType::SC_DELUGE, StatusDeluge{});
	sc.status_map.emplace(StatusType::SC_ASSUMPTIO, StatusAssumptio{});

	for (auto& [type, status] : sc.status_map) {
		std::cout << "cure_statuses for " << static_cast<int>(type) << "\n\t";
		auto i = std::visit([](auto &status) {
			return status.cure_statuses();
		}, status);
		std::cout << " returned " << i << "\n";
	}

	return 0;
}
