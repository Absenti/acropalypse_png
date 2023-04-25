# Acropalypse PNG 

This tool is designed to restore hidden data in PNG files using acropalypse vulnerability. It can detect and display the trailing bytes length, delete hidden data, or restore hidden data and create a new PNG image.

## Dependencies

- Python 3.6 or higher
- Pillow (PIL)
- NumPy

You can install these dependencies using the following command:

```sh
pip install pillow numpy
```

## Usage

The tool can be used with the following command line options:

1. Detect the vulnerability  and display the trailing bytes length:

```sh
python restore_png.py detect <cropped_png>
```
2. Delete the hidden data:


```sh
python restore_png.py delete <cropped_png> <output_png>
```


3. Restore the hidden data and create a new PNG image:

```sh
python restore_png.py restore <type_exploit> <cropped_png> <reconstructed_png>
```

Where <type_exploit> can be either pixel or windows.
