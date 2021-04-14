import { inject, injectable } from "tsyringe";

import { ICarsRepository } from "@modules/cars/repositories/ICarsRepository";
import { Rental } from "@modules/rentals/infra/typeorm/entities/Rental";
import { IRentalsRepository } from "@modules/rentals/repositories/IRentalsRepository";
import { IDateProvider } from "@shared/container/providers/DateProvider/IDateProvider";
import { AppError } from "@shared/errors/AppError";

interface IRequest {
  id: string;
  user_id: string;
}

@injectable()
class DevolutionRentalUseCase {
  constructor(
    @inject("RentalsRepository")
    private rentalsRepository: IRentalsRepository,
    @inject("CarsRepository")
    private carsRepository: ICarsRepository,
    @inject("DayjsDateProvider")
    private dateProvider: IDateProvider
  ) {}

  async execute({ id, user_id }: IRequest): Promise<Rental> {
    const minimum_rent_days = 1;

    const rental = await this.rentalsRepository.findById(id);
    const rentalCarId = rental.car_id;

    const car = await this.carsRepository.findById(rentalCarId);
    const carDailyRate = car.daily_rate;
    const carDailyFineAmount = car.fine_amount;

    if (!rental) {
      throw new AppError("Rental does not exist");
    }

    let rentTotalDays = this.dateProvider.compareInDays(
      rental.start_date,
      this.dateProvider.dateNow()
    );

    rentTotalDays = rentTotalDays <= 0 ? minimum_rent_days : rentTotalDays;

    const rentTotalDelayInDays = this.dateProvider.compareInDays(
      rental.expected_return_date,
      this.dateProvider.dateNow()
    );

    let total = 0;

    if (rentTotalDelayInDays > 0) {
      const calculateFineAmount = rentTotalDelayInDays * carDailyFineAmount;
      total = calculateFineAmount;
    }

    total += rentTotalDays * carDailyRate;

    rental.end_date = this.dateProvider.dateNow();

    rental.total = total;

    await this.rentalsRepository.create(rental);

    await this.carsRepository.updateAvailable(rentalCarId, true);

    return rental;
  }
}

export { DevolutionRentalUseCase };
