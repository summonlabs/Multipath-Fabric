// Multipath Fabric 1.0.0 public umbrella header.
//
// Multipath Fabric is the simultaneous-path-set governance runtime of the
// Distributed Fabric Infrastructure / Fabric OS stack. It owns multipath-set
// identity, membership, generations, threshold semantics, Path Authority
// generation binding, invalidation, revalidation, fencing, snapshots, diffs,
// explanations and versioned persistence.
//
// It does not compute paths, decide path legality, install routes, govern ECMP,
// assign traffic weights, analyse diversity, adapt to congestion or reserve
// bandwidth.
#ifndef MULTIPATH_FABRIC_MULTIPATH_FABRIC_HPP
#define MULTIPATH_FABRIC_MULTIPATH_FABRIC_HPP

#include "multipath_fabric/authority.hpp"
#include "multipath_fabric/client.hpp"
#include "multipath_fabric/diff.hpp"
#include "multipath_fabric/explanation.hpp"
#include "multipath_fabric/fabric.hpp"
#include "multipath_fabric/ids.hpp"
#include "multipath_fabric/lifecycle.hpp"
#include "multipath_fabric/limits.hpp"
#include "multipath_fabric/outcome.hpp"
#include "multipath_fabric/path_authority.hpp"
#include "multipath_fabric/persistence.hpp"
#include "multipath_fabric/server.hpp"
#include "multipath_fabric/snapshot.hpp"
#include "multipath_fabric/socket.hpp"
#include "multipath_fabric/version.hpp"
#include "multipath_fabric/wire.hpp"

#endif  // MULTIPATH_FABRIC_MULTIPATH_FABRIC_HPP
