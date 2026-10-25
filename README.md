# NFSU Most Wanted Nitrous System

A mod for Need for Speed: Underground (2003) that replaces the nitrous system with the nitrous system from Need for Speed: Most Wanted (2005).

## What it does

In the vanilla game, nitrous does not refill during a race: once the bar is empty, it stays empty. This mod changes the nitrous to work the way it does in Most Wanted: after you use it and wait for a short cooldown, the bar refills itself over time.

The refill rate is not constant. It depends on your speed:

- At higher speeds the bar refills faster. At low speeds the refill is slower.
- The refill starts only after a cooldown that begins when you use the nitrous.
- The refill does not advance while the game is paused.

## Options (ini file)

A `NFSUMostWantedNitrousSystem.ini` file is created next to the mod with these settings:

- `FastRefill` - makes the refill faster: it starts working at lower speeds, stops scaling at higher speeds, and the cooldown after using the nitrous is shorter. (0 = Off, 1 = On)

## How it works technically

The mod reads the game's own nitrous values (current amount, capacity, and boost state) directly from the car structures inside Speed.exe, found by reverse engineering the game, so it does not depend on memory pointer chains that can break. Speed is read from the same value the speedometer displays, in the same units (mph or km/h) you have set in the game options.

## Installation

1. Install the Ultimate ASI Loader (dinput8.dll) into the game folder.
2. Copy `NFSUMostWantedNitrousSystem.asi` into the game folder, next to Speed.exe.
3. Launch the game and start a race.
