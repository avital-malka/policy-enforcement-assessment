# Policy Enforcement Assessment: Stage 1

Implementation for managing network policies.

## Prerequisites

Before running the application, make sure you have the following prerequisites installed:
- Python 3.11.4
## Installation

To install the application, you'll need to have Python 3.11.4 installed on your system. Then, follow these step:
1. Create a virtual environment and install packages: `pip install -r requirements.txt`


## Assumptions and Design Considerations
1. Documentation Approach:
While I usually prefer code readability over docstrings,
I understand that well-written documentation is crucial for maintaining clear code and enabling collaboration. 
As a result, I've included detailed docstrings in this exercise, 
even though it's not my typical approach. 
This is because I believe they are expected as part of the exercise requirements.

2. Don't change the signature of the class or methods:
Adding decorators is acceptable.

3. Allow extra key in the json data:
It is assumed that the create_policy() function can accept JSON data with additional fields and will access only
the relevant fields (such as "name" and "description"). No exceptions will be raised if extra fields are submitted.

4. Code Formatting: 
In accordance with PEP8 guidelines, the recommended line length is kept at 79 characters. This practice optimizes code
readability and supports effective code review processes. However, in some scenarios, developers might extend line 
lengths to 100 or 120 characters to accommodate specific project needs. 
I run the flake8 command and ignore warning if the length is less than 120.
5. Implement name uniqueness:
The project's core requirement is that policy names should be unique to avoid ambiguity and ensure proper management.
I considered using Pydantic's `@field_validator('name')` to validate unique policy names: 
    ```python
    # Example validation mechanism (not actually used in the project)
    @field_validator('name')
    def validate_unique_name(cls, name: str) -> str:
        if name in cls.policy_names:
            raise ValueError(f"A policy with the name '{name}' already exists. Please choose a unique name.")
        policy_names.append(name)
        return name
    ```

    While this concept was contemplated, the approach of utilizing @field_validator to enforce name uniqueness was not incorporated into the final implementation.
    
    Handling Name Removal and Persistent Cache
    Initially, an alternative approach involved using the __del__ method to remove names from the policy_names list. However, this strategy proved to be unreliable due to uncertainties concerning when the garbage collector would execute. Instead, a more dependable solution involves storing data in a persistent cache. This allows us to define a unique field within that context, ensuring a consistent and robust solution for managing policy names.
    At the end i implemented the memory storage as the task required.
