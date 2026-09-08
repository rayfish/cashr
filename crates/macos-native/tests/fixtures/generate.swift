import AppKit
import CoreImage

let directory = CommandLine.arguments[1]
let context = CIContext(options: [.useSoftwareRenderer: true])
func code(_ text: String) -> CIImage {
    let filter = CIFilter(name: "CIQRCodeGenerator")!
    filter.setValue(Data(text.utf8), forKey: "inputMessage")
    filter.setValue("M", forKey: "inputCorrectionLevel")
    let qr = filter.outputImage!
    let background = CIImage(color: .white).cropped(to: qr.extent.insetBy(dx: -4, dy: -4))
    return qr.composited(over: background).transformed(by: CGAffineTransform(scaleX: 6, y: 6))
}
func save(_ image: CIImage, _ name: String) throws {
    let cg = context.createCGImage(image, from: image.extent)!
    let bitmap = NSBitmapImageRep(cgImage: cg)
    try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: directory + "/" + name))
}
let pairing = "nostrconnect://" + String(repeating: "a", count: 64) + "?relay=wss%3A%2F%2Frelay.example.com&secret=qr-test"
try save(code(pairing), "qr-pairing.png")
let first = code("cashr-test-one")
let second = code("cashr-test-two").transformed(by: CGAffineTransform(translationX: first.extent.width + 32, y: 0))
let bounds = first.extent.union(second.extent)
let background = CIImage(color: .white).cropped(to: bounds)
try save(first.composited(over: second.composited(over: background)), "qr-multiple.png")
try save(CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: 100, height: 100)), "qr-blank.png")
