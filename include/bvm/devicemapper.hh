/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#ifndef INCLUDE_BVM_DEVICEMAPPER_HH_
#define INCLUDE_BVM_DEVICEMAPPER_HH_

#define FMT_STRING_ALIAS 1
#include <fmt/format.h>

#include <libdevmapper.h>
#include <exception>
#include <memory>
#include <string>
#include <vector>

namespace bvm {
struct Target {
  Target(size_t start, size_t size, std::string target, std::string args)
      : start_sector{start},
        sectors{size},
        target_type{target},
        target_args{args} {}
  size_t start_sector;
  size_t sectors;
  std::string target_type;
  std::string target_args;
};

class Task {
 public:
  ~Task() {
    if (dmt_ != nullptr) dm_task_destroy(dmt_);
  }

  explicit Task(int type) : dmt_{nullptr}, cookie_{0} {
    if (!(dmt_ = dm_task_create(type))) {
      throw std::runtime_error("Failed to create task");
    }
  }

  void set_cookie(uint16_t udev_flags = 0) {
    if (!dm_task_set_cookie(dmt_, &cookie_, udev_flags)) {
      throw std::runtime_error("Failed to set cookie for task");
    }
  }

  void set_name(const std::string& name) {
    if (!dm_task_set_name(dmt_, name.c_str())) {
      throw std::runtime_error(
          fmt::format("Failed to set name for task to {}", name));
    }
  }

  void enable_checks() {
    if (!dm_task_enable_checks(dmt_)) {
      throw std::runtime_error("Failed to enable checks for task");
    }
  }

  void add_target(const Target& target) {
    if (!dm_task_add_target(dmt_, target.start_sector, target.sectors,
                            target.target_type.c_str(),
                            target.target_args.c_str())) {
      // fmt::print("Failed adding linear target\n");
      // fmt::print("start={}, sectors={}, type=linear, args='{}'\n", start,
      // sectors, target_args);
      throw std::runtime_error(
          fmt::format("Error adding target: {} {} {} {}", target.start_sector,
                      target.sectors, target.target_type, target.target_args));
    }
  }

  void get_info(dm_info& dmi) {
    if (!dm_task_get_info(dmt_, &dmi)) {
      throw std::runtime_error("Failed to get info from task");
    }
  }

  void run() {
    if (!dm_task_run(dmt_)) {
      throw std::runtime_error("Failed to run task");
    }
  }

 private:
  dm_task* dmt_;
  uint32_t cookie_;
};

class DeviceMapper {
 public:
  using target_type = Target;
  using targets_type = std::vector<target_type>;

  static std::shared_ptr<dm_info> create(std::string name,
                                         const targets_type& targets) {
    Task task(DM_DEVICE_CREATE);
    task.set_name(name);
    task.enable_checks();
    task.set_cookie();
    for (const auto& tgt : targets) {
      task.add_target(tgt);
    }
    task.run();
    auto dmi = std::make_shared<dm_info>();
    task.get_info(*dmi);
    return dmi;
  }

  static void remove(const std::string& name) {
    Task task(DM_DEVICE_REMOVE);
    task.set_name(name);
    task.enable_checks();
    task.set_cookie();
    task.run();
  }
};

}  // namespace bvm

#endif  // INCLUDE_BVM_DEVICEMAPPER_HH_

