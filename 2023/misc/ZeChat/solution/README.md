[COMMUNITY WRITEUP](https://hackmd.io/@Chivato/SkN3Piyan)

#### generate.html

```html
<!DOCTYPE html>
<html>
    <head>
        <title>Sunburst with Dots</title>
        <style>
            body {
                margin: 0;
                overflow: hidden;
            }
            canvas {
                display: block;
            }
        </style>
    </head>
    <body>
        <canvas id="code"></canvas>

        <script>
            const data = "INTIGRITI{w3ch47_d474_3nc0d1n6_ftw!!!}";
            const metadata = "1337"; //4 CHARS MAX
            const amountOfRays = 36; // Change this value for different amounts of rays
            const dotsPerRay = 13; // Change this value for different dots per ray

            function text2Binary(input) {
                var characters = input.split("");

                return characters
                    .map(function (char) {
                        const binary = char.charCodeAt(0).toString(2);
                        const pad = Math.max(8 - binary.length, 0);
                        // Just to make sure it is 8 bits long.
                        return "0".repeat(pad) + binary;
                    })
                    .join("");
            }
            const debug = false;
            const debugColors = ["red", "gray", "green"];
            const model = [
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 0, 0, 2, 1, 1, 3, 3, 3, 4, 3, 3, 3] /* Search map */,
                [0, 0, 0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 0, 0, 2, 1, 1, 3, 3, 3, 4, 3, 3, 3] /* Search map */,
                [0, 0, 0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 3, 3, 3, 3, 3, 3, 3, 3] /* Begin of app logo */,
                [0, 0, 0, 2, 3, 3, 3, 3, 3, 5, 3, 3, 3] /* Middle of app logo */,
                [0, 0, 0, 2, 1, 3, 3, 3, 3, 3, 3, 3, 3] /* End of app logo */,
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 0, 0, 2, 1, 1, 3, 3, 3, 4, 3, 3, 3] /* Search map */,
                [0, 0, 0, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
                [0, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 0],
            ];
            const map = [];

            const binaryData = text2Binary(data);

            const binaryMetadata = text2Binary(metadata);

            function mapData() {
                let binaryDataPos = 0;
                let binaryMetadataPos = 0;
                //First, calculate all the regular data
                for (i = 0; i < model.length; i++) {
                    map[i] = [];
                    for (var j = 0; j < model[i].length; j++) {
                        map[i][j] = null;
                        var dotType = model[i][j];
                        if (dotType == 1) {
                            if (binaryData[binaryDataPos] == "1") {
                                //Actual data
                                map[i][j] = 1;
                            }
                            binaryDataPos++;
                        } else if (dotType == 2) {
                            if (binaryMetadata[binaryMetadataPos] == "1") {
                                //Metadata
                                map[i][j] = 1;
                            }
                            binaryMetadataPos++;
                        }
                    }
                }
                /*
                Any masks / transformations can happen here
            */
                //Now, check the patches
                for (i = 0; i < model.length; i++) {
                    for (var j = 0; j < model[i].length; j++) {
                        var dotType = model[i][j];
                        if (dotType == 0) {
                            //Edge data
                            if (j == 0) {
                                //If it's the first dot in the line, it's always black (inner patch)
                                map[i][j] = 1;
                            } else if (j == dotsPerRay - 1 && map[i][j - 1] == 1) {
                                //edge patch, now it depends if the previous was also black
                                map[i][j] = 1;
                            }
                        }
                    }
                }
            }

            function drawMap() {
                const canvas = document.getElementById("code");
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
                const ctx = canvas.getContext("2d");
                const centerX = canvas.width / 2;
                const centerY = canvas.height / 2;
                const dotSpacing = 4;
                const dotRadius = 6;

                const maxRayLength = Math.min(centerX, centerY);

                const centerCircleRadius = 100;
                const centerCirclePadding = 20;

                ctx.translate(centerX, centerY);

                ctx.beginPath();
                ctx.arc(0, 0, centerCircleRadius, 0, 2 * Math.PI);
                ctx.fillStyle = "black";
                ctx.fill();

                for (var i = 0; i < dotsPerRay; i++) {
                    //Helper lines
                    ctx.beginPath();
                    ctx.strokeStyle = "gray";
                    ctx.lineWidth = 1;
                    ctx.moveTo(0, 0);
                    ctx.arc(0, 0, centerCirclePadding + centerCircleRadius + dotRadius * 2 * i, 0, 2 * Math.PI);
                    ctx.stroke();
                }

                ctx.rotate((225 * Math.PI) / 180 - 4 * (((360 / amountOfRays) * Math.PI) / 180));

                for (let i = 0; i < amountOfRays; i++) {
                    const angle = (i * 360) / amountOfRays;
                    const radianAngle = (angle * Math.PI) / 180;
                    const endX = centerX + maxRayLength * Math.cos(radianAngle);
                    const endY = centerY + maxRayLength * Math.sin(radianAngle);

                    //Helper lines
                    ctx.beginPath();
                    ctx.strokeStyle = "gray";
                    ctx.lineWidth = 1;
                    ctx.moveTo(0, 0);
                    ctx.lineTo(endX, 0);
                    ctx.stroke();

                    for (let j = 0; j < dotsPerRay; j++) {
                        const dotX = centerCirclePadding + centerCircleRadius + dotRadius * 2 * j;
                        var dotType = model[i][j];

                        //Draw normal Dot
                        if (dotType < 3) {
                            //These can contain actual data
                            if (debug) {
                                ctx.fillStyle = debugColors[dotType];
                            } else {
                                if (map[i][j] == 1) {
                                    ctx.fillStyle = "black";

                                    if (map[i][j + 1] == 1) {
                                        ctx.beginPath();
                                        ctx.strokeStyle = "black";
                                        ctx.lineWidth = dotRadius * 2;
                                        ctx.moveTo(dotX, 0);
                                        ctx.lineTo(dotX + dotRadius * 2, 0);
                                        ctx.stroke();
                                    }
                                } else {
                                    ctx.fillStyle = "transparent";
                                }
                            }
                            ctx.beginPath();
                            ctx.arc(dotX, 0, dotRadius, 0, 2 * Math.PI);
                            ctx.fill();
                        } else if (dotType == 4) {
                            ctx.fillStyle = "black";
                            ctx.beginPath();
                            ctx.arc(dotX, 0, dotRadius * 4, 0, 2 * Math.PI);
                            ctx.fill();

                            ctx.fillStyle = "white";
                            ctx.beginPath();
                            ctx.arc(dotX, 0, dotRadius * 3, 0, 2 * Math.PI);
                            ctx.fill();

                            ctx.fillStyle = "black";
                            ctx.beginPath();
                            ctx.arc(dotX, 0, dotRadius, 0, 2 * Math.PI);
                            ctx.fill();
                        } else if (dotType == 5) {
                            ctx.fillStyle = "black";
                            ctx.beginPath();
                            ctx.arc(dotX, 0, dotRadius * 9, 0, 2 * Math.PI);
                            ctx.fill();
                        }
                    }

                    ctx.rotate(((360 / amountOfRays) * Math.PI) / 180);
                }
            }

            mapData();
            drawMap();
        </script>
    </body>
</html>
```
