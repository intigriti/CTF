from PIL import Image, ImageDraw

# Load the QR code image
qr_code_image = Image.open("qr_code.png")
width, height = qr_code_image.size
half_width, half_height = width // 2, height // 2

squares = {
    "1": (0, 0, half_width, half_height),                     # Top-left
    "2": (half_width, 0, width, half_height),                 # Top-right
    "3": (0, half_height, half_width, height),                # Bottom-left
    "4": (half_width, half_height, width, height)             # Bottom-right
}


# Function to split each square into two triangles
def split_square_into_triangles(img, box):
    x0, y0, x1, y1 = box
    # Define triangle points
    a_triangle_points = [(x0, y0), (x1, y0), (x0, y1)]
    b_triangle_points = [(x1, y1), (x1, y0), (x0, y1)]

    # Crop and mask each triangle
    def crop_triangle(points):
        mask = Image.new("L", img.size, 0)
        draw = ImageDraw.Draw(mask)
        draw.polygon(points, fill=255)
        triangle_img = Image.new("RGBA", img.size)
        triangle_img.paste(img, (0, 0), mask)
        return triangle_img.crop((x0, y0, x1, y1))

    return crop_triangle(a_triangle_points), crop_triangle(b_triangle_points)


# Split each quadrant into triangles and store them
triangle_images = {}
for key, box in squares.items():
    triangle_images[f"{key}a"], triangle_images[f"{key}b"] = split_square_into_triangles(
        qr_code_image, box)

# Define the order of triangles for each half of the square
a_order = ["3", "1", "4", "2"]  # Specify quadrants for "a" triangles
b_order = ["2", "4", "1", "3"]  # Specify quadrants for "b" triangles

# Define the positions for the 4 quadrants
final_positions = [
    (0, 0),                     # Top-left
    (half_width, 0),            # Top-right
    (0, half_height),           # Bottom-left
    (half_width, half_height)   # Bottom-right
]

# Create a blank image to hold the reconstructed QR code
reconstructed_image = Image.new("RGBA", qr_code_image.size)

# Assemble the image using a_order and b_order for each quadrant
for i in range(4):
    # Map each entry in a_order and b_order to the corresponding triangle
    a_triangle = triangle_images[f"{a_order[i]}a"]
    b_triangle = triangle_images[f"{b_order[i]}b"]

    # Create a new square combining the "a" and "b" triangles
    combined_square = Image.new("RGBA", (half_width, half_height))
    combined_square.paste(a_triangle, (0, 0))
    combined_square.paste(b_triangle, (0, 0), b_triangle)

    # Paste the combined square into the final reconstructed image
    reconstructed_image.paste(combined_square, final_positions[i])

# Save the reconstructed image
reconstructed_image.save("obscured.png")
print("Reconstructed QR code saved as 'obscured.png'")
