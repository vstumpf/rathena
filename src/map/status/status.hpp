#ifndef STATUS_STATUS_HPP
#define STATUS_STATUS_HPP

#include <memory>
#include <iostream>


template<typename Derived>
class Status {
public:
	// hardcoded cure statuses
	int cure_statuses(/*struct block_list& bl, status_change &sc*/) {
		std::cout << "Status::cure_statuses()";
		return 0;
	}

protected:
	Status() = default;
	Status(const Status&) = default;
	Status(Status&&) = default;


	inline Derived& as_underlying() {
		return static_cast<Derived&>(*this);
	}
	inline Derived const& as_underlying() const {
		return static_cast<const Derived&>(*this);
	}
	
	// check immunities

	friend Derived;
};

#endif
