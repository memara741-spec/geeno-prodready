import AsyncStorage from "@react-native-async-storage/async-storage";
import { supabase } from "./supabase";

export async function signIn(email: string, password: string) {
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
  await AsyncStorage.setItem("access_token", data.session.access_token);
  await AsyncStorage.setItem("refresh_token", data.session.refresh_token);
  return data.user;
}

export async function signOut() {
  await supabase.auth.signOut();
}
