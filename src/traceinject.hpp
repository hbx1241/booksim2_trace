// Trace-driven traffic manager for HACIMI BookSim integration.

#ifndef _TRACEINJECT_HPP_
#define _TRACEINJECT_HPP_

#include <list>
#include <map>
#include <string>
#include <vector>

#include "trafficmanager.hpp"

class TraceTrafficManager : public TrafficManager {
private:
  struct TraceEvent {
    std::string msg_id;
    int source;
    int dest;
    int flits;
    int release_cycle;
  };

  std::vector<TraceEvent> _events;
  std::vector<TraceEvent>::size_type _next_event;
  std::list<TraceEvent> _ready_events;
  std::map<int, std::string> _pid_to_msg;
  std::ostream * _trace_output;
  bool _owns_trace_output;

  void _LoadTrace(std::string const & path);
  void _PromoteReadyEvents();
  void _GenerateTracePacket(TraceEvent const & event, int cl = 0);

protected:
  virtual void _Inject();
  virtual void _RetireFlit(Flit *f, int dest);
  virtual bool _SingleSim();

public:
  TraceTrafficManager(Configuration const & config, std::vector<Network *> const & net);
  virtual ~TraceTrafficManager();
};

#endif
