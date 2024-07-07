#include "novice.hpp"

#include "skillrepository.hpp"


#include "map/clif.hpp"
#include "map/skill.hpp"
#include "map/status.hpp"


FirstAid::FirstAid() : Skill(e_skill::NV_FIRSTAID) {};

int FirstAid::castendNoDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    clif_skill_nodamage(src, target, skill_id_, 5, 1);
    status_heal(target, 5, 0, 0);
    return 0;
}


void init_novice_skills(SkillRepository& repo) {
    repo.addSkill(e_skill::NV_FIRSTAID, std::make_unique<FirstAid>());
    repo.addSkill(e_skill::NV_TRICKDEAD, std::make_unique<ToggleSkill>(e_skill::NV_TRICKDEAD));
}
