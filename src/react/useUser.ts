// Loaded user record (identity + encrypted wallets), cached on AuthProvider.
import { useAuthContext } from "./AuthProvider.js";
import type { UserData } from "../core/types.js";

export interface UseUserResult {
  user: UserData | null;
  loading: boolean;
  refetch: () => Promise<void>;
}

export function useUser(): UseUserResult {
  const { user, userLoading, refetchUser } = useAuthContext();
  return { user, loading: userLoading, refetch: refetchUser };
}
