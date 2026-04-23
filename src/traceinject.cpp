// Trace-driven traffic manager for HACIMI BookSim integration.

#include <algorithm>
#include <cassert>
#include <fstream>
#include <limits>
#include <sstream>

#include "booksim.hpp"
#include "random_utils.hpp"
#include "traceinject.hpp"

TraceTrafficManager::TraceTrafficManager(
    Configuration const & config,
    std::vector<Network *> const & net)
    : TrafficManager(config, net), _next_event(0), _trace_output(NULL), _owns_trace_output(false)
{
  std::string const trace_input = config.GetStr("trace_input_file");
  if(trace_input.empty()) {
    Error("trace_input_file must be set when traffic = trace.");
  }
  std::string const trace_output = config.GetStr("trace_output_file");
  if(trace_output.empty()) {
    Error("trace_output_file must be set when traffic = trace.");
  }

  _LoadTrace(trace_input);

  if(trace_output == "-") {
    _trace_output = &std::cout;
  } else {
    std::ofstream * out = new std::ofstream(trace_output.c_str());
    if(!out->good()) {
      delete out;
      Error("Unable to open trace output file: " + trace_output);
    }
    _trace_output = out;
    _owns_trace_output = true;
  }
}

TraceTrafficManager::~TraceTrafficManager()
{
  if(_owns_trace_output && _trace_output) {
    delete _trace_output;
    _trace_output = NULL;
  }
}

void TraceTrafficManager::_LoadTrace(std::string const & path)
{
  std::ifstream input(path.c_str());
  if(!input.good()) {
    Error("Unable to open trace input file: " + path);
  }

  std::string line;
  while(std::getline(input, line)) {
    std::string::size_type begin = line.find_first_not_of(" \t\r\n");
    if(begin == std::string::npos) {
      continue;
    }
    std::string::size_type end = line.find_last_not_of(" \t\r\n");
    std::string trimmed = line.substr(begin, end - begin + 1);
    if(trimmed.empty() || (trimmed[0] == '#')) {
      continue;
    }
    std::istringstream iss(trimmed);
    TraceEvent event;
    iss >> event.msg_id >> event.source >> event.dest >> event.flits >> event.release_cycle;
    if(!iss || event.msg_id.empty()) {
      Error("Invalid trace line: " + trimmed);
    }
    if((event.source < 0) || (event.source >= _nodes) ||
       (event.dest < 0) || (event.dest >= _nodes)) {
      Error("Trace packet source/destination out of range: " + trimmed);
    }
    if(event.flits < 0) {
      Error("Trace packet flit count must be >= 0: " + trimmed);
    }
    _events.push_back(event);
  }

  std::sort(
      _events.begin(),
      _events.end(),
      [](TraceEvent const & lhs, TraceEvent const & rhs) {
        if(lhs.release_cycle != rhs.release_cycle) {
          return lhs.release_cycle < rhs.release_cycle;
        }
        return lhs.msg_id < rhs.msg_id;
      });
}

void TraceTrafficManager::_PromoteReadyEvents()
{
  while((_next_event < _events.size()) &&
        (_events[_next_event].release_cycle <= _time)) {
    _ready_events.push_back(_events[_next_event]);
    ++_next_event;
  }
}

void TraceTrafficManager::_GenerateTracePacket(TraceEvent const & event, int cl)
{
  int const pid = _cur_pid++;
  assert(_cur_pid);
  ++_packet_seq_no[event.source];
  ++_requestsOutstanding[event.source];

  bool record = false;
  if((_sim_state == running) ||
     ((_sim_state == draining) && (event.release_cycle < _drain_time))) {
    record = _measure_stats[cl];
  }

  bool const watch = gWatchOut && (_packets_to_watch.count(pid) > 0);
  int const subnetwork = RandomInt(_subnets - 1);

  for(int i = 0; i < event.flits; ++i) {
    Flit * f = Flit::New();
    f->id = _cur_id++;
    assert(_cur_id);
    f->pid = pid;
    f->watch = watch | (gWatchOut && (_flits_to_watch.count(f->id) > 0));
    f->subnetwork = subnetwork;
    f->src = event.source;
    f->ctime = event.release_cycle;
    f->record = record;
    f->cl = cl;
    f->type = Flit::ANY_TYPE;

    _total_in_flight_flits[f->cl].insert(std::make_pair(f->id, f));
    if(record) {
      _measured_in_flight_flits[f->cl].insert(std::make_pair(f->id, f));
    }

    if(i == 0) {
      f->head = true;
      f->dest = event.dest;
    } else {
      f->head = false;
      f->dest = -1;
    }

    switch(_pri_type) {
    case class_based:
      f->pri = _class_priority[cl];
      break;
    case age_based:
      f->pri = std::numeric_limits<int>::max() - event.release_cycle;
      break;
    case sequence_based:
      f->pri = std::numeric_limits<int>::max() - _packet_seq_no[event.source];
      break;
    default:
      f->pri = 0;
      break;
    }

    f->tail = (i == (event.flits - 1));
    f->vc = -1;
    _partial_packets[event.source][cl].push_back(f);
  }

  _pid_to_msg.insert(std::make_pair(pid, event.msg_id));
}

void TraceTrafficManager::_Inject()
{
  _PromoteReadyEvents();
  std::list<TraceEvent>::iterator iter = _ready_events.begin();
  while(iter != _ready_events.end()) {
    if(_partial_packets[iter->source][0].empty()) {
      if(iter->flits > 0) {
        _GenerateTracePacket(*iter, 0);
      }
      iter = _ready_events.erase(iter);
    } else {
      ++iter;
    }
  }
}

void TraceTrafficManager::_RetireFlit(Flit *f, int dest)
{
  if(f->tail) {
    std::map<int, std::string>::iterator iter = _pid_to_msg.find(f->pid);
    if(iter != _pid_to_msg.end()) {
      if(_trace_output) {
        (*_trace_output) << iter->second << " " << f->atime << std::endl;
      }
      _pid_to_msg.erase(iter);
    }
  }
  TrafficManager::_RetireFlit(f, dest);
}

bool TraceTrafficManager::_SingleSim()
{
  _ClearStats();
  _sim_state = running;
  for(int s = 0; s < _nodes; ++s) {
    _qdrained[s].assign(_classes, true);
  }

  while((_next_event < _events.size()) ||
        !_ready_events.empty() ||
        _PacketsOutstanding()) {
    _Step();
  }

  _sim_state = draining;
  _drain_time = _time;
  UpdateStats();
  return true;
}
