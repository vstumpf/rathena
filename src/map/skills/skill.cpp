// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder
#include <common/showmsg.hpp>

#include "skill.hpp"
#include "map/battle.hpp"
#include "map/skill.hpp"
#include "map/clif.hpp"
#include "map/map.hpp"
#include "map/status.hpp"

uint16_t Skill::getSkillId() const {
    return skill_id_;
}

int Skill::castendDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    throw SkillNotImplementedException(skill_id_);
}

int Skill::castendNoDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    throw SkillNotImplementedException(skill_id_);
}

int Skill::castendPositionImpl() const {
    throw SkillNotImplementedException(skill_id_);
}

int Skill::castendDamage(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    try {
        ShowDebug("Skill %d castendDamage\n", skill_id_);
        return castendDamageImpl(src, target, skill_lv, tick, flag);
    } catch (SkillNotImplementedException e) {
        ShowWarning("castendDamage: %s\n", e.what());
        clif_skill_damage(src, target, tick, status_get_amotion(src),
                          status_get_status_data(target)->dmotion, 0,
                          abs(skill_get_num(skill_id_, skill_lv)), skill_id_,
                          skill_lv, skill_get_hit(skill_id_));
        return 1;
    }
}

int Skill::castendNoDamage(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    try {
        ShowDebug("castendNoDamage: %d\n", skill_id_);
        return castendNoDamageImpl(src, target, skill_lv, tick, flag);
    } catch (SkillNotImplementedException e) {
        ShowWarning("castendNoDamage: %s\n", e.what());
        clif_skill_damage(src, target, tick, status_get_amotion(src),
                          status_get_status_data(target)->dmotion, 0,
                          abs(skill_get_num(skill_id_, skill_lv)), skill_id_,
                          skill_lv, skill_get_hit(skill_id_));
        return 1;
    }
}

int WeaponSkill::castendDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    skill_attack(BF_WEAPON, src, src, target, skill_id_, skill_lv, tick, flag);
    return 0;
};

int StatusSkill::castendNoDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    enum sc_type type = skill_get_sc(skill_id_);

    int duration = skill_get_time(skill_id_, skill_lv);
    duration = sc_start(src, target, type, 100, skill_lv, duration);
    clif_skill_nodamage(src, target, skill_id_, skill_lv, duration);
    return 0;
}

int ToggleSkill::castendNoDamageImpl(block_list *src, block_list *target, uint16 skill_lv, t_tick tick, int flag) const {
    enum sc_type type = skill_get_sc(skill_id_);
    struct status_change *tsc = status_get_sc(target);
    struct status_change_entry *tsce = (tsc && type != SC_NONE) ? tsc->getSCE(type) : nullptr;

    int duration = skill_get_time(skill_id_, skill_lv);

    if (tsce) {
        duration = status_change_end(target, type);
    } else {
        duration = sc_start(src, target, type, 100, skill_lv, skill_get_time(skill_id_, skill_lv));
    }
    clif_skill_nodamage(src, target, skill_id_, skill_lv, duration);
    return 0;
}
