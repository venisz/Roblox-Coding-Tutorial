# Roblox-Coding-Tutorial
First lets start off with for iv in pairs so heres an example!
![logo](https://github.com/venisz/Roblox-Coding-Tutorial/assets/82700599/a56a1ad4-cf0f-49c0-a2c9-b19f8e2597ea)


```
for i, v in pairs(game:GetService("workspace"):GetChildren()) do
    v.Anchored = false
end
```
As you may see the map falls apart how fun is that

You can do many cool stuff with it just like this

https://github.com/venisz/Roblox-Coding-Tutorial/assets/82700599/a9b137cd-9af3-4a67-ba66-2aec5fad4c41

Now since you should understand iv in pairs its time for a challenge

Make the entire map or a certaint object or a few certaint objects change size and position each second

Now since you're done with that its time for a diffrent subject






# User-Input-Service
Very sure this is even more simpilier than iv pairs for an example

```
local UIS = game:GetService("UserInputService")

UIS.InputBegan:Connect(function(i)
	if i.KeyCode == Enum.KeyCode.E then
		game.Players.LocalPlayer:Destroy()
	end
end)
```


![image](https://github.com/venisz/Roblox-Coding-Tutorial/assets/82700599/69c679fe-65f6-4adc-bec5-1ffa35fe8399)


 As you can see when you test it you get kicked cause your player is removed

# Players
For getting players u can do a few diffrent ways like
```
local Players = game:GetService("Players")
--for server stuff
```
or
```
local players = game.Players.LocalPlayer
```
To get to the humanoid you can also do
```
local hum = game.Players.LocalPlayer.Character.Humanoid
```

Now since you know that for the challenge your gona make whenever u press e with userinputservice ur jump power goes to 100 and ur walkspeed to. Using Humanoid properties
