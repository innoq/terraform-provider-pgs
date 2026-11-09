package pgs

import "context"

// CheckKeyConflicts reports a key already registered for an account other than ownerID (0 = a new
// account). It is a read-only plan-time version of the check Create and Update run when applying.
func (s *Store) CheckKeyConflicts(ctx context.Context, ownerID int64, keys []KeyInput) error {
	return s.checkKeyConflicts(ctx, ownerID, keys)
}

// ClaimKeys records, for the lifetime of this provider process, that the account `owner` wants
// these keys, and returns the name of another account that already claimed one of them in the same
// run ("" if none). A repeated call for the same owner replaces that owner's earlier claim. This is
// how two pgs_account resources in one configuration are caught sharing a key at plan time: every
// resource is planned by the same provider process, but none of them can see the others' config.
func (s *Store) ClaimKeys(owner string, keys []KeyInput) (key, otherOwner string) {
	s.claimMu.Lock()
	defer s.claimMu.Unlock()
	if s.claims == nil {
		s.claims = map[string]string{}
	}
	for k, o := range s.claims {
		if o == owner {
			delete(s.claims, k)
		}
	}
	for _, k := range keys {
		if o, ok := s.claims[k.Normalized]; ok {
			return k.Normalized, o
		}
	}
	for _, k := range keys {
		s.claims[k.Normalized] = owner
	}
	return "", ""
}
