fn main() {
    println!("Hello, World!");
    println!("Welcome to the MigTD examples directory!");
    
    // Demonstrate some basic Rust features
    let message = "This is a simple Rust application";
    println!("{}", message);
    
    // Create a vector and iterate through it
    let numbers = vec![1, 2, 3, 4, 5];
    println!("Numbers: {:?}", numbers);
    
    // Calculate sum
    let sum: i32 = numbers.iter().sum();
    println!("Sum of numbers: {}", sum);
    
    // String manipulation
    let name = "MigTD";
    let greeting = format!("Hello from {}!", name);
    println!("{}", greeting);
    
    println!("Hello World application completed successfully!");
}
