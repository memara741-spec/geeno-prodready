import { useEffect, useState } from "react";
import { FlatList, Text, View } from "react-native";
import * as Location from "expo-location";
import { supabase } from "../lib/supabase";

export default function Home() {
  const [checkins, setCheckins] = useState<any[]>([]);

  useEffect(() => {
    (async () => {
      await Location.requestForegroundPermissionsAsync();
      const { data, error } = await supabase.from("checkins").select("id, trail, lat, lng").limit(50);
      if (!error) setCheckins(data ?? []);
    })();
  }, []);

  return (
    <View>
      <FlatList data={checkins} keyExtractor={(c) => c.id} renderItem={({ item }) => <Text>{item.trail}</Text>} />
    </View>
  );
}
