import AsyncStorage from "@react-native-async-storage/async-storage";
import Constants from "expo-constants";
import { createClient } from "@supabase/supabase-js";

const extra = Constants.expoConfig?.extra as { supabaseUrl: string; supabaseServiceKey: string };

export const supabase = createClient(extra.supabaseUrl, extra.supabaseServiceKey, {
  auth: { storage: AsyncStorage, persistSession: true, autoRefreshToken: true },
});
