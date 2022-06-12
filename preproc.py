import os
import cv2

path = 'testing_artifacts/input'
output = 'testing_artifacts/temps'
segment_output = 'testing_artifacts/segments'

def preprocess(img):
    image = cv2.imread(img)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    blur = cv2.GaussianBlur(gray, (7,7), 0)
    thresh = cv2.threshold(blur, 0, 255, cv2.THRESH_BINARY_INV+ cv2.THRESH_OTSU)[1]

    kernal = cv2.getStructuringElement(cv2.MORPH_RECT, (10, 8))
    dialate = cv2.dilate(thresh, kernal, iterations=1)

    name = img.split('\\')[-1].split('.')[0]
    print(name)
    name_dialated = os.path.join(output, f'dialated_{name}.png')
    cv2.imwrite(name_dialated, dialate)

    # find contours
    cnts = cv2.findContours(dialate, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    cnts = cnts[0] if len(cnts) ==2 else cnts[1]

    cnts = sorted(cnts, key=lambda x: cv2.boundingRect(x)[0])
    count = 0


    for c in cnts:
        x, y, w, h = cv2.boundingRect(c)
        if h > 10 and w > 10:
            roi = image[y:y+h, x:x+w]
            seg = os.path.join(segment_output, name, f"{count}.png")
            # cv2.imwrite(seg, roi)
            count+=1
            cv2.rectangle(image, (x,y), (x+w, y+h), (36, 255, 12), 2)

    
    name_bbox = os.path.join(output, f'bbox_{name}.png')
    cv2.imwrite(name_bbox, image)


for image in os.listdir(path):
    print(image)
    preprocess(os.path.join(path, image))