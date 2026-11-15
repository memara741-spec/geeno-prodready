import { useState } from "react";
import { Button, Text, TextInput, View } from "react-native";
import { CameraView } from "expo-camera";
import { signIn, signOut } from "../lib/session";

export default function Profile() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  return (
    <View>
      <Text>Account</Text>
      <TextInput placeholder="Email" value={email} onChangeText={setEmail} />
      <TextInput placeholder="Password" secureTextEntry value={password} onChangeText={setPassword} />
      <Button title="Sign in" onPress={() => signIn(email, password)} />
      <Button title="Sign out" onPress={signOut} />
      <CameraView style={{ height: 200 }} />
    </View>
  );
}
