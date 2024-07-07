#pragma once

#include "skillrepository.hpp"

class FirstAid : public Skill {
public:
    FirstAid();

    virtual int castendNoDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const override;
};

void init_novice_skills(SkillRepository& repo);
